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

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {   //创建server socket（默认端口21）并判断成功与否
        printf("create socket error!\n");
        exit(1);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));        //设置与socket关联的选项
    bzero(&server_addr, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sockfd, (struct sockaddr *) (&server_addr), sizeof(struct sockaddr));
    listen(sockfd, 1);    //监听此端口

    return sockfd;
}

int checkPasswd(char *name, char *passwd) {
    struct spwd *shd = getspnam(name);        //访问shadow口令，返回spwd结构的指针
    if (shd != NULL) {
        static char crypt_char[80];
        strcpy(crypt_char, shd->sp_pwdp);        //将加密口令赋给crypt_char
        char salt[130];
        int i = 0, j = 0;
        while (shd->sp_pwdp[i] != '\0') {
            salt[i] = shd->sp_pwdp[i];
            if (salt[i] == '$') {
                j++;
                if (j == 3) {
                    salt[i + 1] = '\0';
                    break;
                }
            }
            i++;
        }
        if (j < 3)
            return -1;
        if (strcmp(crypt(passwd, salt), shd->sp_pwdp) ==
            0)      //passwd：待加密字符串 ； salt：影响加密结果的字符串； 调用crypt进行计算，得到加密密码字段； 在调用strcmp进行比较，‘=0’代表一样
            return 0;
    }
    return -1;
}

int checkPortPasv(Ftpd *ftp) {
    if (ftp->pasv_fd > 0 || ftp->port_addr != NULL) {
        return 0;
    }
    writeMsg(ftp, 425, "Use PORT/PASV first");
    return -1;
}

int getTransferFD(Ftpd *ftp, char *msg) {
    int sockfd;
    if (ftp->port_addr != NULL) {
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            return -1;
        if (connect(sockfd, (struct sockaddr *) (ftp->port_addr), sizeof(struct sockaddr)) == -1) {
            close(sockfd);
            return -1;
        }
    } else {
        sockfd = accept(ftp->pasv_fd, NULL, 0);
        if (sockfd < 0) {
            return -1;
        }
        //setsockopt_keepalive(sockfd);
    }
    if (ftp->pasv_fd > 0) {
        close(ftp->pasv_fd);
        ftp->pasv_fd = -1;
    }
    if (ftp->port_addr != NULL) {
        free(ftp->port_addr);
        ftp->port_addr = NULL;
    }
    if (sockfd < 0) {
        writeMsg(ftp, 425, "Use PORT/PASV first");
        return -1;
    }
    writeMsg(ftp, 150, msg);
    return sockfd;
}

int getFtpCmd(Ftpd *ftp)        //获取ftp命令 正确返回0 错误返回-1
{
    int len;
    int i;
    while (1) {
        while (1) {
            len = recv(ftp->fd, ftp->cmd, sizeof(ftp->cmd), MSG_PEEK);       //MSG_PEEK 窥看外来消息
            if (len == -1 && errno == EINTR)         // 产合错误的原因是：因为阻塞，调用可能无法返回
                continue;
            else if (len < 0)
                return -1;
            break;
        }
        for (i = 0; i < len; i++) {
            if (ftp->cmd[i] == '\n') {
                if (read(ftp->fd, ftp->cmd, i + 1) != i + 1)
                    return -1;
                break;
            }
        }
        if (i >= len)
            continue;
        if (i >= 0 && ftp->cmd[i] == '\n') {
            i--;
            if (i >= 0 && ftp->cmd[i] == '\r')
                i--;
            ftp->cmd[i + 1] = '\0';
        }
        ftp->arg = strchr(ftp->cmd, ' ');
        if (ftp->arg != NULL)
            *ftp->arg++ = '\0';
        break;
    }
    return 0;
}

void login(Ftpd *ftp) {
    struct passwd *pw = NULL;
    while (1) {
        if (getFtpCmd(ftp) < 0)
            exit(-1);
        if (strcmp(ftp->cmd, "USER") == 0) {
            strcpy(ftp->username, ftp->arg);     //将arg中的内容赋给username
            pw = getpwnam(ftp->username);          //获取用户登录相关信息
            printf("Receive username: %s\n", ftp->username);
            writeMsg(ftp, 331, "Please enter password");
        } else if (strcmp(ftp->cmd, "PASS") == 0) {
            //pw_encrypt("sss","sdf",1);
            //if(check_password(pw, ftp->arg)>0)
            if (checkPasswd(ftp->username, ftp->arg) == 0)
                break;
            writeMsg(ftp, 530, "Login failed");
            pw = NULL;
        } else if (strcmp(ftp->cmd, "QUIT") == 0) {
            writeMsg(ftp, 221, "GoodBye");
            return;
        } else {
            writeMsg(ftp, 530, "Login with USER and PASS");
        }
    }
    writeMsg(ftp, 230, "Login successful");
}

void handlePWD(Ftpd *ftp)       //PWD
{
    char buf[1024] = {0};

    getcwd(buf, sizeof(buf));
    writeMsg(ftp, 257, buf);
    printInfo(ftp, "PWD successfull");
}

void handleCWD(Ftpd *ftp)       //CWD
{
    if (!ftp->arg || chdir(ftp->arg) != 0) {      //chdir: 改变当前工作目录 0:成功 -1:失败  优先级大到小： !  !=  ||
        writeMsg(ftp, 550, "CWD Error");
        printInfo(ftp, "CWD failed");
        return;
    }
    writeMsg(ftp, 250, "CWD successful");
    printInfo(ftp, "CWD successfull");
}

void handleCDUP(Ftpd *ftp)      //CDUP 打开上一级目录
{
    if (chdir("..") != 0) {         //chdir: 改变当前工作目录 0:成功 -1:失败
        writeMsg(ftp, 550, "CDUP Error");
        printInfo(ftp, "CDUP failed");
        return;
    }
    writeMsg(ftp, 250, "CDUP successful");
    printInfo(ftp, "CDUP successfull");
}

void lsCommon(Ftpd *ftp, int type) {
    int rfd;
    char buf[1024];
    int len;
    FILE *fp = NULL;

    if (ftp->arg)
        printf("%s\n", ftp->arg);
    if (checkPortPasv(ftp))
        goto ERR;
    if (type == 0)
        sprintf(buf, "ls -l");
    else
        sprintf(buf, "ls");
    if (ftp->arg)
        sprintf(buf + strlen(buf), " %s", ftp->arg);
    if ((fp = popen(buf, "r")) == NULL) {
        writeMsg(ftp, 450, "ERROR");
        goto ERR;
    }
    sprintf(buf, "Directory listing");
    rfd = getTransferFD(ftp, buf);
    if (rfd < 0)
        goto ERR;
    while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (len != write(rfd, buf, len))
            break;
    }
    if (type == 0) {
        writeMsg(ftp, 226, "LIST successfull");
        printInfo(ftp, "LIST successfull");
    } else {
        writeMsg(ftp, 226, "NLST successfull");
        printInfo(ftp, "NLST successfull");
    }
    close(rfd);
    pclose(fp);
    return;
    ERR:
    if (type == 0)
        printInfo(ftp, "LIST failed");
    else
        printInfo(ftp, "NLST failed");
    if (fp != NULL)
        pclose(fp);
}

void handleLIST(Ftpd *ftp) {
    lsCommon(ftp, 0);
}

void handleNLST(Ftpd *ftp) {
    lsCommon(ftp, 1);
}

void handleMKD(Ftpd *ftp)                           //MKD 创建目录
{
    if (!ftp->arg || mkdir(ftp->arg, 0777) != 0) {         //mkdir: 创建目录  参数1:新创建目录的目录名  参数2:指定该目录的访问权限     0:成功 -1:失败
        writeMsg(ftp, 550, "MKD Error");
        printInfo(ftp, "MKD failed");
        return;
    }
    writeMsg(ftp, 257, "MKD successful");
    printInfo(ftp, "MKD successfull");
}

void handleRMD(Ftpd *ftp)                           //RMD 删除空目录
{
    if (ftp->arg == NULL || rmdir(ftp->arg) != 0) {         //rmdir: 删除空目录     0:成功 -1:失败
        writeMsg(ftp, 550, "RMD Error");
        printInfo(ftp, "RMD failed");
        return;
    }
    writeMsg(ftp, 250, "RMD successful");
    printInfo(ftp, "RMD successfull");
}

void handleDELE(Ftpd *ftp)                          //DELE 从文件系统中删除一个指定名字的文件
{
    if (ftp->arg == NULL || unlink(ftp->arg) != 0) {        //unlink: 从文件系统中删除一个指定名字的文件    0:成功 -1:失败
        writeMsg(ftp, 550, "DELE Error");
        printInfo(ftp, "DELE failed");
        return;
    }
    writeMsg(ftp, 250, "DELE successful");
    printInfo(ftp, "DELE successfull");
}

void handleRNFR(Ftpd *ftp) {
    if (ftp->rnfr)
        free(ftp->rnfr);            //释放所指向的一块内存空间
    if (ftp->arg == NULL) {
        writeMsg(ftp, 501, "Path is NULL");
        printInfo(ftp, "RNFR failed");
        return;
    }
    ftp->rnfr = strdup(ftp->arg);     //strdup: 先用malloc()配置与参数字符串相同的空间大小，然后将参数字符串的内容复制到该内存地址，然后把该地址返回
    writeMsg(ftp, 350, "RNFR successful");
    printInfo(ftp, "RNFR successfull");
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
    if (rename(ftp->rnfr, ftp->arg)) {             //rename: 重命名文件或目录   第一个参数：oldname  第二个参数：newname   0:成功 -1:失败
        writeMsg(ftp, 550, "rename Error");
        printInfo(ftp, "RNTO failed");
    } else {
        writeMsg(ftp, 250, "RNTO successful");
        printInfo(ftp, "RNTO successfull");
    }
    free(ftp->rnfr);
    ftp->rnfr = NULL;
}

void handlePORT(Ftpd *ftp) {      // PROT h1,h2,h3,h4,p1,p2
    char *p;
    int port, i;

    if (ftp->arg == NULL)
        goto ERR;
    if (ftp->pasv_fd > 0) {
        close(ftp->pasv_fd);
        ftp->pasv_fd = -1;
    }
    if (ftp->port_addr == NULL)
        ftp->port_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    if ((p = strrchr(ftp->arg, ',')) ==
        NULL)     //strrchr(const char *s, int c): 表示在字符串s中从后到前查找字符c，返回字符c第一次在字符串s中出现的位置，如果未找到字符c，则返回NULL
        goto ERR;
    *p = '\0';
    if ((port = atoi(p + 1)) > 255)
        goto ERR;
    if ((p = strrchr(ftp->arg, ',')) == NULL)
        goto ERR;
    *p = '\0';
    if ((port += (atoi(p + 1) << 8)) > 0xffff)       // <<8 左移8比特 因为是p1，p1需要乘以256
        goto ERR;
    for (p = ftp->arg; *p != '\0'; p++)        // h1,h2,h3,h4 变为 h1.h2.h3.h4
        if (*p == ',')
            *p = '.';
    bzero(ftp->port_addr, sizeof(struct sockaddr_in));
    ftp->port_addr->sin_family = AF_INET;
    ftp->port_addr->sin_port = htons(port);
    if (inet_pton(AF_INET, ftp->arg, &ftp->port_addr->sin_addr) <= 0)
        goto ERR;
    writeMsg(ftp, 200, "PORT successful");
    printInfo(ftp, "PORT successfull");
    printf("Active Mode On\n");
    printf("Connect client %s On Tcp Port %d\n", inet_ntoa(ftp->port_addr->sin_addr), ntohs(ftp->port_addr->sin_port));
    return;
    ERR:
    if (ftp->port_addr != NULL) {
        free(ftp->port_addr);
        ftp->port_addr = NULL;
    }
    writeMsg(ftp, 500, "BAD CMD");
    printInfo(ftp, "PORT failed");
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

void handleRETR(Ftpd *ftp) {
    int xfd = -1;
    int rfd;
    struct stat statbuf;
    char buf[1024];
    int len;
    int total = 0;
    struct timeval start, end;

    if (ftp->arg)
        printf("%s\n", ftp->arg);
    if (checkPortPasv(ftp))
        goto ERR;
    xfd = ftp->arg ? open(ftp->arg, O_RDONLY) : -1;
    if (xfd < 0) {
        writeMsg(ftp, 550, "Cann't open file");
        goto ERR;
    }
    if (fstat(xfd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
        writeMsg(ftp, 550, "is not reg file");
        goto ERR;
    }
    sprintf(buf, "Opening BINARY connection for %s (%lu bytes)", ftp->arg, statbuf.st_size);
    rfd = getTransferFD(ftp, buf);
    if (rfd < 0)
        goto ERR;
    gettimeofday(&start, NULL);
    while ((len = read(xfd, buf, sizeof(buf))) > 0) {
        if (len != write(rfd, buf, len))
            break;
        total += len;
    }
    if (total != statbuf.st_size) {
        writeMsg(ftp, 451, "Less than total");
        goto ERR;
    }
    writeMsg(ftp, 226, "RETR successfull");
    printInfo(ftp, "RETR successfull");
    gettimeofday(&end, NULL);
    double ttime = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
    printf("%d bytes sended in %f secs (%f kB/s)\n", total, ttime / 1000000, total * 1000000.0 / 1024 / ttime);
    close(rfd);
    close(xfd);
    return;
    ERR:
    printInfo(ftp, "RETR failed");
    if (xfd > 0)
        close(xfd);
}

void handleSTOR(Ftpd *ftp) {
    int xfd = -1;
    int rfd;
    struct stat statbuf;
    char buf[1024];
    int len;
    int total = 0;
    struct timeval start, end;

    if (ftp->arg)
        printf("%s\n", ftp->arg);
    if (checkPortPasv(ftp))
        goto ERR;
    xfd = ftp->arg ? open(ftp->arg, O_WRONLY | O_CREAT | O_TRUNC, 0666) : -1;
    if (xfd < 0) {
        writeMsg(ftp, 550, "Cann't open file");
        goto ERR;
    }
    if (fstat(xfd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
        writeMsg(ftp, 553, "is not reg file");
        goto ERR;
    }
    rfd = getTransferFD(ftp, "Ok to send data");
    if (rfd < 0)
        goto ERR;
    gettimeofday(&start, NULL);
    while ((len = read(rfd, buf, sizeof(buf))) > 0) {
        if (len != write(xfd, buf, len))
            break;
        total += len;
    }
    if (total == 0) {
        writeMsg(ftp, 451, "BADSENDFILE");
        goto ERR;
    }
    writeMsg(ftp, 226, "RETR successfull");
    printInfo(ftp, "RETR successfull");
    gettimeofday(&end, NULL);
    double ttime = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
    printf("%d bytes received in %f secs (%f kB/s)\n", total, ttime / 1000000, total * 1000000.0 / 1024 / ttime);
    close(rfd);
    close(xfd);
    return;
    ERR:
    printInfo(ftp, "RETR failed");
    if (xfd > 0)
        close(xfd);
}

void ftpdloop(int fd) {
    Ftpd *ftp = (Ftpd *) calloc(1, sizeof(Ftpd));        //在动态存储区中分配1个长度为sizeof(Ftpd)的连续空间，函数返回一个指向分配起始地址的指针

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
        } else if (strcmp(ftp->cmd, "MKD") == 0) {        //MKD 创建目录
            printInfo(ftp, "MKD");
            handleMKD(ftp);
        } else if (strcmp(ftp->cmd, "RMD") == 0) {        //RMD 删除空目录
            printInfo(ftp, "RMD");
            handleRMD(ftp);
        } else if (strcmp(ftp->cmd, "DELE") == 0) {       //DELE 从文件系统中删除一个指定名字的文件
            printInfo(ftp, "DELE");
            handleDELE(ftp);
        } else if (strcmp(ftp->cmd, "RNFR") == 0) {       //RNFR与RNTO 重命名文件或目录
            printInfo(ftp, "RNFR");
            handleRNFR(ftp);
        } else if (strcmp(ftp->cmd, "RNTO") == 0) {       //RNFR与RNTO 重命名文件或目录
            printInfo(ftp, "RNTO");
            handleRNTO(ftp);
        } else if (strcmp(ftp->cmd, "PORT") == 0) {       //active mode，告诉server，client端用于接受数据连接的端口号
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

    svrfd = createServerSock(21);   //默认端口21，返回svrfd
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
