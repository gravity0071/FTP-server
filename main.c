#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <stddef.h>
#include <shadow.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

typedef struct   //定义结构体Ftpd
{
    int fd;
    char cmd[8192];
    char *arg;
    char username[50];
    struct sockaddr_in *port_addr;
    int pasv_fd;     //passive file descriptor
    char *rnfr;
} Ftpd;

void writeMsg(Ftpd *ftp, int code, char *msg) {
    char buf[1024];
    if (msg != NULL)
        sprintf(buf, "%d %s\r\n", code, msg);  //将内容写到buf里面
    else
        sprintf(buf, "%d\r\n", code);
    write(ftp->fd, buf, strlen(buf));     //在client显示buf里面的内容
}

void printInfo(Ftpd *ftp, char *info) {
    char buf[512];
    getcwd(buf, sizeof(buf));        //获取当前工作目录
    printf("%s\t%s\texecute %s\n", ftp->username, buf, info);
}

int createServerSock(int port)  //创建server socket（默认端口21）
{
    int sockfd;
    int reuse = 1;
    struct sockaddr_in server_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {   //creats a server socket（default port 21)
        printf("create socket error!\n");
        exit(1);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse,
               sizeof(reuse));        //SO_REUSEADDR: allows the socket to reuse the address if it's in the TIME_WAIT state
    bzero(&server_addr, sizeof(struct sockaddr_in)); //zero out the memory
    //bind socket to address and port
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port); //convert the port number to network byte
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); //allows connection to any ip address
    bind(sockfd, (struct sockaddr *) (&server_addr), sizeof(struct sockaddr));
    listen(sockfd, 1);    //监听此端口

    return sockfd;
}

int checkPasswd(char *name, char *passwd) {
    struct spwd *shd = getspnam(name);        // Retrieve shadow password entry
    if (shd != NULL) {
        static char crypt_char[80];
        strcpy(crypt_char, shd->sp_pwdp);     // Copy hashed password into crypt_char (may not be necessary)

        char salt[130];   // Buffer for the salt
        int i = 0, j = 0;
        while (shd->sp_pwdp[i] !=
               '\0') {    // Extract the salt from the hashed password, The hashed password uses a format like $id$salt$hashed_password
            salt[i] = shd->sp_pwdp[i];
            if (salt[i] == '$') {            // Look for the third '$'
                j++;
                if (j == 3) {                // After the third '$', we stop
                    salt[i + 1] = '\0';      // Terminate the salt string
                    break;
                }
            }
            i++;
        }
        if (j < 3)                           // If the salt is incomplete, return an error
            return -1;

        // Hash the input password using the extracted salt and compare with the stored hash
        if (strcmp(crypt(passwd, salt), shd->sp_pwdp) == 0)
            return 0;    // Password is correct
    }
    return -1;   // Password is incorrect or user not found
}

int checkPortPasv(Ftpd *ftp) {
    if (ftp->pasv_fd > 0 || ftp->port_addr != NULL) { //Check if PASV or PORT is Active
        return 0;
    }
    writeMsg(ftp, 425, "Use PORT/PASV first");
    return -1;
}

int getTransferFD(Ftpd *ftp,
                  char *msg) { //*msg: A message that is sent to the client after successfully establishing a data transfer connection.
    int sockfd;

    // Active Mode (PORT command)
    if (ftp->port_addr != NULL) {
        // Create a socket for outgoing connection
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            return -1;

        // Connect to the client at the provided port address
        if (connect(sockfd, (struct sockaddr *) (ftp->port_addr), sizeof(struct sockaddr)) == -1) {
            close(sockfd);
            return -1;
        }
    } else {
        // Passive Mode (PASV command)
        // Accept the incoming connection from the client
        sockfd = accept(ftp->pasv_fd, NULL, 0);
        if (sockfd < 0) {
            return -1;
        }
        // Optionally set socket options, e.g., keep-alive (commented out in your code)
        // setsockopt_keepalive(sockfd);
    }

    // Clean up after connection
    if (ftp->pasv_fd > 0) {
        close(ftp->pasv_fd);  // Close passive mode socket if it was open
        ftp->pasv_fd = -1;
    }

    if (ftp->port_addr != NULL) {
        free(ftp->port_addr);  // Free the port address if it was in active mode
        ftp->port_addr = NULL;
    }

    // Error handling for socket creation failure
    if (sockfd < 0) {
        writeMsg(ftp, 425, "Use PORT/PASV first");  // Send error message to the client
        return -1;
    }

    // Send success message to the client, e.g., "150 File status okay; about to open data connection"
    writeMsg(ftp, 150, msg);

    return sockfd;  // Return the socket file descriptor for the data transfer
}

int getFtpCmd(Ftpd *ftp) {
    int len;
    int i;
    while (1) {
        // Peek at incoming data to see if a complete command is available
        while (1) {
            len = recv(ftp->fd, ftp->cmd, sizeof(ftp->cmd), MSG_PEEK);  // Peek into the buffer
            if (len == -1 && errno == EINTR)  // If interrupted by a signal, retry
                continue;
            else if (len < 0)  // If recv failed, return error
                return -1;
            break;
        }

        // Look for a newline character (indicating end of command)
        for (i = 0; i < len; i++) {
            if (ftp->cmd[i] == '\n') {  // Newline indicates the end of the command
                if (read(ftp->fd, ftp->cmd, i + 1) != i + 1)  // Read full command into buffer cmd, from position i + 1
                    return -1;
                break;
            }
        }

        //the command has been successfully read into the buffer
        // If no newline found, continue waiting for more data
        if (i >= len)
            continue;

        // Strip the trailing newline and carriage return characters
        //since the terminate char should be \r\n
        if (i >= 0 && ftp->cmd[i] == '\n') {
            i--;
            if (i >= 0 && ftp->cmd[i] == '\r')
                i--;
            ftp->cmd[i + 1] = '\0';  // Null-terminate the command string
        }

        // Separate the command and its argument (if any)
        ftp->arg = strchr(ftp->cmd, ' ');  // Look for a space separating the command and argument
        if (ftp->arg != NULL)
            *ftp->arg++ = '\0';  // set a null Terminate the command and point to the argument

        break;  // Break out of the loop since we have successfully processed a command
    }
    return 0;  // Command successfully received and processed
}

void login(Ftpd *ftp) {
    struct passwd *pw = NULL;
    while (1) {
        // Get the FTP command, exit on error
        if (getFtpCmd(ftp) < 0)
            exit(-1);

        // If the command is "USER", handle the username
        if (strcmp(ftp->cmd, "USER") == 0) {
            strcpy(ftp->username, ftp->arg);     // Copy the argument (username) to ftp->username
            pw = getpwnam(ftp->username);        // Retrieve user login-related information
            printf("Receive username: %s\n", ftp->username);  // Print the received username
            writeMsg(ftp, 331, "Please enter password");   // Send 331 (username OK, need password)
        }

            // If the command is "PASS", handle the password
        else if (strcmp(ftp->cmd, "PASS") == 0) {
            // If the password is correct, break out of the loop (login success)
            if (checkPasswd(ftp->username, ftp->arg) == 0)
                break;
            writeMsg(ftp, 530, "Login failed");  // Send 530 (login failure)
            pw = NULL;  // Reset the user info
        }

            // If the command is "QUIT", handle the exit
        else if (strcmp(ftp->cmd, "QUIT") == 0) {
            writeMsg(ftp, 221, "GoodBye");  // Send 221 (goodbye message)
            return;  // Exit the login function
        }

            // If none of the above, send an error message
        else {
            writeMsg(ftp, 530, "Login with USER and PASS");  // Send 530 (ask to login properly)
        }
    }

    // Send 230 (login successful)
    writeMsg(ftp, 230, "Login successful");
}

//FTP PWD (Print Working Directory)
void handlePWD(Ftpd *ftp) {
    char buf[1024] = {0}; //hold the current working directory path

    getcwd(buf, sizeof(buf));
    writeMsg(ftp, 257, buf); // response code 257, which indicates “Path created”
    printInfo(ftp, "PWD successfull");
}

//FTP CWD (Change Working Directory)
void handleCWD(Ftpd *ftp) {
    // Check if argument is present and attempt to change the directory
    if (!ftp->arg || chdir(ftp->arg) != 0) {  // Check if no argument or directory change fails
        writeMsg(ftp, 550, "CWD Error");      // Send error message to client (550)
        printInfo(ftp, "CWD failed");         // Log failure
        return;                               // Exit the function
    }

    // If successful, send success message to client
    writeMsg(ftp, 250, "CWD successful");     // Send success message (250)
    printInfo(ftp, "CWD successful");         // Log success
}

// CDUP (Change to Parent Directory) command
void handleCDUP(Ftpd *ftp) {
    // Attempt to change the directory to the parent directory ("..")
    if (chdir("..") != 0) {         // chdir: Changes the current working directory, returns 0 on success, -1 on failure
        writeMsg(ftp, 550, "CDUP Error");   // Send an error message (550) to the client if the directory change failed
        printInfo(ftp, "CDUP failed");      // Log that the CDUP command failed
        return;                             // Exit the function
    }

    writeMsg(ftp, 250, "CDUP successful");  // Send a success message (250) to the client
    printInfo(ftp, "CDUP successful");      // Log that the CDUP command was successful
}

void lsCommon(Ftpd *ftp, int type) {
    int rfd;               // File descriptor for the data connection
    char buf[1024];        // Buffer to store command output and messages
    int len;               // Length of data read
    FILE *fp = NULL;       // Pointer for the command output file

    // If there is an argument (directory or file name), print it for debugging
    if (ftp->arg)
        printf("%s\n", ftp->arg);

    // Check if the client has properly set up PORT or PASV mode
    if (checkPortPasv(ftp))
        goto ERR;  // If not, jump to error handling

    // Build the "ls" command, with "ls -l" for LIST and "ls" for NLST
    if (type == 0)
        sprintf(buf, "ls -l");  // LIST command (detailed directory listing): sprintf: write the data into the buf
    else
        sprintf(buf, "ls");     // NLST command (simple directory listing)

    // If there's an argument (specific directory or file), append it to the command
    if (ftp->arg)
        sprintf(buf + strlen(buf), " %s", ftp->arg); //buf + strlen(buf) points to the end of the current string in buf

    // Open a pipe to execute the "ls" command and read its output
    if ((fp = popen(buf, "r")) == NULL) { // the ls is being executed here
        writeMsg(ftp, 450, "ERROR");  // Send error message if the command failed to execute
        goto ERR;  // Jump to error handling
    }

    // Send a message indicating that the directory listing is starting
    sprintf(buf, "Directory listing");
    rfd = getTransferFD(ftp, buf);  // Get the file descriptor for the data connection
    if (rfd < 0)
        goto ERR;  // If data connection setup failed, jump to error handling

    // Read the output of the "ls" command and send it to the client
    while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (len != write(rfd, buf, len))  // Write the data to the client and check for errors
            break;  // If an error occurs, break the loop
    }

    // If this is a LIST command, send success messages
    if (type == 0) {
        writeMsg(ftp, 226, "LIST successful");
        printInfo(ftp, "LIST successful");
    } else {  // If this is a NLST command, send NLST success messages
        writeMsg(ftp, 226, "NLST successful");
        printInfo(ftp, "NLST successful");
    }

    close(rfd);  // Close the data connection
    pclose(fp);  // Close the command output pipe
    return;

    ERR:  // Error handling block
    if (type == 0)
        printInfo(ftp, "LIST failed");  // Log failure for LIST command
    else
        printInfo(ftp, "NLST failed");  // Log failure for NLST command

    if (fp != NULL)
        pclose(fp);  // Close the pipe if it was opened
}

void handleLIST(Ftpd *ftp) {
    lsCommon(ftp, 0);
}

void handleNLST(Ftpd *ftp) {
    lsCommon(ftp, 1);
}

// MKD (Make Directory) command
void handleMKD(Ftpd *ftp) {
    // Check if the argument (directory name) is provided and try to create the directory
    if (!ftp->arg || mkdir(ftp->arg, 0777) !=
                     0) {  // mkdir: create directory; argument 1: directory name; argument 2: access permissions (0777), allowing read, write, and execute permissions
        writeMsg(ftp, 550, "MKD Error");  // Send error message (550) to the client if directory creation fails
        printInfo(ftp, "MKD failed");     // Log that the MKD command failed
        return;                           // Exit the function if an error occurred
    }

    writeMsg(ftp, 257, "MKD successful");  // Send success message (257) to the client if directory creation succeeded
    printInfo(ftp, "MKD successful");      // Log that the MKD command was successful
}

// RMD (Remove Directory) command
void handleRMD(Ftpd *ftp) {
    // Check if the argument (directory name) is provided and try to remove the directory
    if (ftp->arg == NULL ||
        rmdir(ftp->arg) != 0) {  // rmdir: removes an empty directory; returns 0 on success, -1 on failure
        writeMsg(ftp, 550, "RMD Error");  // Send error message (550) to the client if directory removal fails
        printInfo(ftp, "RMD failed");     // Log that the RMD command failed
        return;                           // Exit the function if an error occurred
    }
    writeMsg(ftp, 250, "RMD successful");  // Send success message (250) to the client if directory removal succeeded
    printInfo(ftp, "RMD successful");      // Log that the RMD command was successful
}

// DELE (Delete File) command
void handleDELE(Ftpd *ftp) {
    // Check if the argument (file name) is provided and try to delete the file
    if (ftp->arg == NULL ||
        unlink(ftp->arg) != 0) {  // unlink: deletes a file from the file system; returns 0 on success, -1 on failure
        writeMsg(ftp, 550, "DELE Error");  // Send error message (550) to the client if file deletion fails
        printInfo(ftp, "DELE failed");     // Log that the DELE command failed
        return;                            // Exit the function if an error occurred
    }

    writeMsg(ftp, 250, "DELE successful");  // Send success message (250) to the client if file deletion succeeded
    printInfo(ftp, "DELE successful");      // Log that the DELE command was successful
}

// RNFR (Rename From) command
void handleRNFR(Ftpd *ftp) {
    // If the ftp->rnfr pointer is not NULL, free the previously allocated memory to avoid memory leaks
    if (ftp->rnfr)
        free(ftp->rnfr);            // Free the memory that was allocated earlier for rnfr

    // Check if the argument (file/directory path) is provided
    if (ftp->arg == NULL) {         // If no path is provided, send an error message to the client
        writeMsg(ftp, 501, "Path is NULL");
        printInfo(ftp, "RNFR failed");
        return;
    }

    // Duplicate the path provided by the client and store it in ftp->rnfr
    ftp->rnfr = strdup(ftp->arg);   // strdup allocates memory, copies the string, and returns the pointer to it

    writeMsg(ftp, 350,
             "RNFR successful");
    printInfo(ftp, "RNFR successful");
}

void handleRNTO(Ftpd *ftp) {
    if (ftp->rnfr == NULL) {
        writeMsg(ftp, 503, "Use RNFR first");
        printInfo(ftp, "RNTO failed");
        return;
    }
    if (ftp->arg == NULL) {
        writeMsg(ftp, 501, "Path is NULL");
        printInfo(ftp, "RNTO failed");
        return;
    }
    if (rename(ftp->rnfr,
               ftp->arg)) {         // rename: renames file/directory; argument 1: oldname, argument 2: newname        writeMsg(ftp, 550, "rename Error");
        printInfo(ftp, "RNTO failed");
    } else {
        writeMsg(ftp, 250, "RNTO successful");
        printInfo(ftp, "RNTO successfull");
    }
    free(ftp->rnfr);
    ftp->rnfr = NULL;
}


void handlePORT(
        Ftpd *ftp) {      // PORT command: h1,h2,h3,h4,p1,p2 the client’s IP address (h1.h2.h3.h4) and a port number formed by combining p1 and p2.
    char *p;
    int port, i;

    // Check if the argument (h1,h2,h3,h4,p1,p2) is provided
    if (ftp->arg == NULL)
        goto ERR;

    // If in passive mode, close the passive mode socket
    if (ftp->pasv_fd > 0) {
        close(ftp->pasv_fd);     // Close the passive mode socket
        ftp->pasv_fd = -1;
    }

    // Allocate memory for the client's address if it's not already allocated
    if (ftp->port_addr == NULL)
        ftp->port_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

    // Find the last comma in the argument string to get p2
    if ((p = strrchr(ftp->arg, ',')) == NULL)    // strrchr(): find the last occurrence of ',' in ftp->arg
        goto ERR;
    *p = '\0';  // Terminate the string at the last comma
    if ((port = atoi(p + 1)) > 255)   // Convert p2 to an integer and check if it's valid
        goto ERR;

    // Find the next comma (for p1) and process it
    if ((p = strrchr(ftp->arg, ',')) == NULL)
        goto ERR;
    *p = '\0';  // Terminate the string at the next comma
    if ((port += (atoi(p + 1) << 8)) > 0xffff)   // Add p1 (shifted by 8 bits) to p2, making the full port number
        goto ERR;

    // Replace the remaining commas in h1,h2,h3,h4 with dots to form an IP address
    for (p = ftp->arg; *p != '\0'; p++)
        if (*p == ',')
            *p = '.';

    // Clear the port address structure and set up the new address
    bzero(ftp->port_addr, sizeof(struct sockaddr_in));   // Zero out the sockaddr_in structure
    ftp->port_addr->sin_family = AF_INET;                // Set the address family to IPv4
    ftp->port_addr->sin_port = htons(port);              // Convert the port number to network byte order

    // Convert the IP address string to binary form and store it in the sockaddr_in structure
    if (inet_pton(AF_INET, ftp->arg, &ftp->port_addr->sin_addr) <= 0)
        goto ERR;

    // Send a success message to the client
    writeMsg(ftp, 200, "PORT successful");
    printInfo(ftp, "PORT successful");
    printf("Active Mode On\n");
    printf("Connect client %s On Tcp Port %d\n", inet_ntoa(ftp->port_addr->sin_addr), ntohs(ftp->port_addr->sin_port));
    return;

    // Error handling section
    ERR:
    if (ftp->port_addr != NULL) {
        free(ftp->port_addr);  // Free the allocated memory if an error occurs
        ftp->port_addr = NULL;
    }
    writeMsg(ftp, 500, "BAD CMD");  // Send an error message to the client
    printInfo(ftp, "PORT failed");  // Log that the PORT command failed
}

void handlePASV(Ftpd *ftp) {
    int fd;
    unsigned port;
    char *p;
    char addr[20];
    char buf[200];
    struct sockaddr_in localaddr;
    socklen_t len = sizeof(localaddr);

    if (ftp->pasv_fd > 0) {
        close(ftp->pasv_fd);
        ftp->pasv_fd = -1;
    }
    if (ftp->port_addr != NULL) {
        free(ftp->port_addr);
        ftp->port_addr = NULL;
    }
    ftp->pasv_fd = createServerSock(0);
    if (getsockname(ftp->pasv_fd, (struct sockaddr *) &localaddr, &len))
        goto ERR;
    port = ntohs(localaddr.sin_port);
    if (getsockname(ftp->fd, (struct sockaddr *) &localaddr, &len))
        goto ERR;
    strcpy(addr, inet_ntoa(localaddr.sin_addr));
    for (p = addr; *p != '\0'; p++)
        if (*p == '.')
            *p = ',';
    sprintf(buf, "PASV ok (%s,%u,%u)", addr, (int) (port >> 8), (int) (port & 255));
    writeMsg(ftp, 227, buf);
    printInfo(ftp, "PASV successfull");
    printf("Pasv Mode On\n");
    printf("Listen %s On Tcp Port %d\n", inet_ntoa(localaddr.sin_addr), port);
    return;
    ERR:
    if (ftp->pasv_fd != -1) {
        close(ftp->pasv_fd);
        ftp->pasv_fd = -1;
    }
    writeMsg(ftp, 421, "Cann't use");
    printInfo(ftp, "PASV failed");
}

// RETR (Retrieve File) command
void handleRETR(Ftpd *ftp) {
    int xfd = -1;             // File descriptor for the file to be transferred
    int rfd;                  // File descriptor for the data connection
    struct stat statbuf;       // Structure to store file metadata
    char buf[1024];            // Buffer for reading and sending file data
    int len;                   // Number of bytes read or written
    int total = 0;             // Total bytes transferred
    struct timeval start, end; // For measuring transfer time

    // Print the argument (file name) if provided
    if (ftp->arg)
        printf("%s\n", ftp->arg);

    // Check if the client has set up either PORT or PASV mode
    if (checkPortPasv(ftp))
        goto ERR;

    // Open the file for reading (O_RDONLY)
    xfd = ftp->arg ? open(ftp->arg, O_RDONLY) : -1;
    if (xfd < 0) {
        writeMsg(ftp, 550, "Can't open file");  // Send error message if file can't be opened
        goto ERR;
    }

    // Check if the file is a regular file (not a directory or special file)
    if (fstat(xfd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
        writeMsg(ftp, 550, "Is not a regular file");  // Send error message if it's not a regular file
        goto ERR;
    }

    // Send a message to the client about opening a binary connection
    sprintf(buf, "Opening BINARY connection for %s (%lu bytes)", ftp->arg, statbuf.st_size);
    rfd = getTransferFD(ftp, buf);  // Get the file descriptor for the data connection
    if (rfd < 0)
        goto ERR;

    // Start timing the file transfer
    gettimeofday(&start, NULL);

    // Read from the file and send the data to the client in chunks
    while ((len = read(xfd, buf, sizeof(buf))) > 0) {
        if (len != write(rfd, buf, len))  // Write the data to the data connection
            break;  // Break if there is a write error
        total += len;  // Keep track of total bytes transferred
    }

    // Check if the total number of bytes transferred matches the file size
    if (total != statbuf.st_size) {
        writeMsg(ftp, 451, "Transfer incomplete");  // Send error if the transfer was incomplete
        goto ERR;
    }

    // Send success message after the transfer is complete
    writeMsg(ftp, 226, "RETR successful");
    printInfo(ftp, "RETR successful");

    // Stop timing the transfer and calculate the transfer speed
    gettimeofday(&end, NULL);
    double ttime = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
    printf("%d bytes sent in %f secs (%f kB/s)\n", total, ttime / 1000000, total * 1000000.0 / 1024 / ttime);

    // Close the data connection and file descriptors
    close(rfd);
    close(xfd);
    return;

    // Error handling
    ERR:
    printInfo(ftp, "RETR failed");
    if (xfd > 0)
        close(xfd);  // Close the file descriptor if it was opened
}

// STOR (Store File) command
void handleSTOR(Ftpd *ftp) {
    int xfd = -1;             // File descriptor for the file to be stored
    int rfd;                  // File descriptor for the data connection
    struct stat statbuf;       // Structure to store file metadata
    char buf[1024];            // Buffer for reading and writing file data
    int len;                   // Number of bytes read or written
    int total = 0;             // Total bytes transferred
    struct timeval start, end; // For measuring transfer time

    // Print the argument (file name) if provided
    if (ftp->arg)
        printf("%s\n", ftp->arg);

    // Check if the client has set up either PORT or PASV mode
    if (checkPortPasv(ftp))
        goto ERR;

    // Open or create the file for writing, truncating it if it already exists
    xfd = ftp->arg ? open(ftp->arg, O_WRONLY | O_CREAT | O_TRUNC, 0666) : -1;
    if (xfd < 0) {  // If file can't be opened for writing
        writeMsg(ftp, 550, "Can't open file");  // Send error message to the client
        goto ERR;
    }

    // Check if the opened file is a regular file (not a directory or special file)
    if (fstat(xfd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
        writeMsg(ftp, 553, "Is not a regular file");  // Send error if not a regular file
        goto ERR;
    }

    // Get the data connection (active or passive mode) and tell the client it's ok to send data
    rfd = getTransferFD(ftp, "Ok to send data");
    if (rfd < 0)  // If there is an error getting the data connection
        goto ERR;

    // Start timing the file transfer
    gettimeofday(&start, NULL);

    // Read from the data connection and write to the file in chunks
    while ((len = read(rfd, buf, sizeof(buf))) > 0) {
        if (len != write(xfd, buf, len))  // Write the received data to the file
            break;  // Break the loop if there is an error in writing to the file
        total += len;  // Keep track of total bytes received
    }

    // Check if any data was actually transferred
    if (total == 0) {
        writeMsg(ftp, 451, "BADSENDFILE");  // Send error if no data was sent
        goto ERR;
    }

    // Send success message after the transfer is complete
    writeMsg(ftp, 226, "STOR successful");  // Correct message for STOR completion
    printInfo(ftp, "STOR successful");

    // Stop timing the transfer and calculate the transfer speed
    gettimeofday(&end, NULL);
    double ttime = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
    printf("%d bytes received in %f secs (%f kB/s)\n", total, ttime / 1000000, total * 1000000.0 / 1024 / ttime);

    // Close the data connection and the file descriptor
    close(rfd);
    close(xfd);
    return;

    // Error handling block
    ERR:
    printInfo(ftp, "STOR failed");  // Log the failure
    if (xfd > 0)
        close(xfd);  // Close the file descriptor if it was opened
}

void ftpdloop(int fd) {
    Ftpd *ftp = (Ftpd *) calloc(1, sizeof(Ftpd));

    ftp->fd = fd;
    ftp->pasv_fd = -1;
    ftp->port_addr = NULL;

    writeMsg(ftp, 220, "Please enter username");
    login(ftp);
    while (1) {
        if (getFtpCmd(ftp) < 0)
            exit(-1);
        if (strcmp(ftp->cmd, "QUIT") == 0) {
            printInfo(ftp, "QUIT");
            writeMsg(ftp, 221, "GoodBye");
            printInfo(ftp, "QUIT successfull");
            return;
        } else if (strcmp(ftp->cmd, "NOOP") == 0) {
            printInfo(ftp, "NOOP");
            writeMsg(ftp, 200, "NOOP successful");
            printInfo(ftp, "NOOP successfull");
        } else if (strcmp(ftp->cmd, "PWD") == 0) {        //PWD
            printInfo(ftp, "PWD");
            handlePWD(ftp);
        } else if (strcmp(ftp->cmd, "CWD") == 0) {        //CWD
            printInfo(ftp, "CWD");
            handleCWD(ftp);
        } else if (strcmp(ftp->cmd, "CDUP") == 0) {       //CDUP
            printInfo(ftp, "CDUP");
            handleCDUP(ftp);
        } else if (strcmp(ftp->cmd, "LIST") == 0) {
            printInfo(ftp, "LIST");
            handleLIST(ftp);
        } else if (strcmp(ftp->cmd, "NLST") == 0) {
            printInfo(ftp, "NLST");
            handleNLST(ftp);
        } else if (strcmp(ftp->cmd, "MKD") == 0) {        //MKD
            printInfo(ftp, "MKD");
            handleMKD(ftp);
        } else if (strcmp(ftp->cmd, "RMD") == 0) {        //RMD
            printInfo(ftp, "RMD");
            handleRMD(ftp);
        } else if (strcmp(ftp->cmd, "DELE") == 0) {       //DELE
            printInfo(ftp, "DELE");
            handleDELE(ftp);
        } else if (strcmp(ftp->cmd, "RNFR") == 0) {       //RNFR与RNTO
            printInfo(ftp, "RNFR");
            handleRNFR(ftp);
        } else if (strcmp(ftp->cmd, "RNTO") == 0) {       //RNFR与RNTO
            printInfo(ftp, "RNTO");
            handleRNTO(ftp);
        } else if (strcmp(ftp->cmd, "PORT") == 0) {       //active mode
            printInfo(ftp, "PORT");
            handlePORT(ftp);
        } else if (strcmp(ftp->cmd, "PASV") == 0) {
            printInfo(ftp, "PASV");
            handlePASV(ftp);
        } else if (strcmp(ftp->cmd, "RETR") == 0) {
            printInfo(ftp, "RETR");
            handleRETR(ftp);
        } else if (strcmp(ftp->cmd, "STOR") == 0) {
            printInfo(ftp, "STOR");
            handleSTOR(ftp);
        } else {
            writeMsg(ftp, 500, "Unknow CMD");
            printf("Unknow CMD: %s\n", ftp->cmd);
        }
    }
}

int main(int argc, char *argv[]) {
    int svrfd;
    int cltfd;
    int sin_size;
    struct sockaddr_in client_addr;

    svrfd = createServerSock(21);   //default port: 21
    while (1) {
        sin_size = sizeof(struct sockaddr);
        cltfd = accept(svrfd, (struct sockaddr *) (&client_addr), &sin_size);
        printf("Accept client %s on TCP Port %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        if (fork() == 0) {
            close(svrfd);
            ftpdloop(cltfd);
            break;
        } else {
            close(cltfd);
        }
    }
    return 0;
}
