FTP Server Project

Overview

This project involves the design and implementation of an FTP (File Transfer Protocol) server using the C programming language, running on a Linux system. The server allows for user login and supports a variety of FTP commands. It provides both active and passive modes for file transfer and logs user activities.

Features

	•	User login: Authenticate users based on a username and password.
	•	Supported FTP commands:
	•	PWD - Print working directory
	•	CWD - Change working directory
	•	LIST - List files and directories
	•	MKD - Make a new directory
	•	DELE - Delete a file
	•	RNFR/RNTO - Rename a file or directory
	•	File transfer services:
	•	Active mode for file uploads and downloads
	•	Passive mode for file uploads and downloads
	•	User information display:
	•	IP address
	•	Actions performed
	•	Data transfer speed
	•	Total traffic
	•	Action logging: All actions performed by the user are logged and displayed on the server’s side.

Requirements

	•	Programming Language: C
	•	Operating System: Linux
	•	Port: The server listens on port 21 (default FTP port).
	•	Libraries: Standard networking libraries available in C for socket programming.

Functional Modules

	1.	User Login: Authenticate the user by checking credentials against a stored database.
	2.	Command Processing: The server listens for user commands on port 21 and executes FTP commands as listed above.
	3.	File Transfer Modes:
	•	Active mode: The server connects to the client’s specified data port for file transfer.
	•	Passive mode: The server waits for the client to connect for file transfer.
	4.	Logging: Logs user actions, including file transfers and command usage, and prints them on the server console.
