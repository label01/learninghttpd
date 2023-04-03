#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>

#include <errno.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
//typedef __u_short u_short;
#define _XOPEN_SOURCE 500
#define LINE_ENDING "\r\n"

//为了提高accept_request的可读性，增加如下宏定义
#define MAX_REQUEST_SIZE 8192
#define MAX_METHOD_SIZE 255
#define MAX_URL_SIZE 2048
#define MAX_PATH_SIZE 4096


int startup(uint16_t *);
void error_die(const char *);
void accept_request(int);
int get_line(int, char *, int);
void unimplemented(int);
void not_found(int);
void serve_file(int, const char *);
void headers(int ,const char *);
void cat(int, FILE *);
void execute_cgi(int, const char *, const char*, const char *);
void bad_request(int);
void cannot_execute(int);

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(uint16_t *port)
{
    int server_socket = 0;
    struct sockaddr_in server_addr;

    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        error_die("socket");
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(*port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        error_die("bind");
    }
    if (*port == 0)
    {
        socklen_t server_len = sizeof(server_addr);
        if(getsockname(server_socket, (struct sockaddr *)&server_addr, &server_len) == -1)
        {
            error_die("getsockname");
        }
        *port = ntohs(server_addr.sin_port);
    }
    if (listen(server_socket, 5) == -1)
    {
        error_die("listen");
    }
    return(server_socket);    
        

}
/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc){
    perror(sc);
    exit(1);
}
/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(int client_fd){
    printf("enter accept_request");

    char request[MAX_REQUEST_SIZE];
    //初始化request字符串
    memset(request, 0, MAX_REQUEST_SIZE);
    
    //从客户端读取请求
    ssize_t request_len = get_line(client_fd, request, sizeof(request));
    if (request_len < 0){
        perror("Failed to receive request\n");
        return;
    }
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL_SIZE];
    char path[MAX_PATH_SIZE];

    memset(method, 0, MAX_METHOD_SIZE);
    memset(url, 0, MAX_URL_SIZE);
    memset(path, 0, MAX_PATH_SIZE);

    size_t i, j;
    struct stat st;
    /*becomes true if server decides this is a CGI program*/
    int cgi = 0;
    char *query_string = NULL;
    i = 0;
    j = 0;
    while(!ISspace(request[j]) && ( i < sizeof(method) - 1))
    {
        method[i] = request[j];
        i++;
        j++;
    }
    method[i] = '\0';
    //printf("the method is %s\n", method);
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client_fd);
        return;
    }

    if (strcasecmp(method, "POST") == 0)
    {
        printf("this is post ,cgi = 1\n");
        cgi = 1;
    }
    i = 0;
    while (ISspace(request[j]) && (j < sizeof(request)))
    {
        j++;
    }
    while (!ISspace(request[j]) && (i < sizeof(url) -1) && (j < sizeof(request)))
    {
        url[i] = request[j];
        i++;
        j++;
    }
    url[i] = '\0';
    //printf("the url is %s\n", url);
    //处理查询字符
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        while (*query_string != '\0'){
            query_string++;
        }
        while ((*query_string != '?') && (*query_string != '\0'))
        {
            query_string++;
        }
        if (*query_string == '?')
        {
            //printf("enter GET, the cgi = 1\n");
            cgi = 1;
            *query_string = '\0';
            query_string++;
        }
        
    }
    sprintf(path, "htdocs%s", url);
    //printf("the sprintf string is  %s\n", path);
    
    if (path[strlen(path) -1] == '/')
    {
        strcat(path, "index.html");
    }
    if (stat(path, &st) == -1){
        while ((request_len > 0) && strcmp("\n", request))
        {
            request_len = get_line(client_fd, request, sizeof(request));
        }
        not_found(client_fd);
    }
    else{
        if ((st.st_mode & S_IFMT) == S_IFDIR)
        {
            strcat(path, "/index.html");
        }
        if ((st.st_mode & S_IXUSR) || 
            (st.st_mode & S_IXGRP) ||
            (st.st_mode & S_IXOTH) )
        {
            cgi = 1;
        }
        if (!cgi)
        {
            serve_file(client_fd, path);
        }
        else{
            execute_cgi(client_fd, path, method, query_string);
        }
        close(client_fd);

    }

}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    //设置超时时间
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    while((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                if ((n > 0) && (c == '\n'))
                {
                    recv(sock, &c, 1, 0);
                }
                else{
                    c = '\n';
                }
            }
            buf[i] = c;
            i++;
        }
        //处理错误码
        else if (n == -1){
            if (errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            else{
                break;
            }
        }
        else{
            c = '\n';
        }
    }
    buf[i] = '\0';
    return(i);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported. \r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);

}
/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client){
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE> NOT Found </TITLE> \r\n" );
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P> The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML> \r\n");
    send(client, buf, strlen(buf), 0);

}
/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
    printf("enter the serve file\n");
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A';
    buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf))
    {
        numchars = get_line(client, buf, sizeof(buf));
    }
    resource = fopen(filename, "r");
    if (resource == NULL)
    {
        not_found(client);
    }
    else{
        headers(client, filename);
        cat(client, resource);
    }
    fclose(resource);
}


/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
    char buf[1024];
    (void)filename;

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}
/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
    char buf[1024];
    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
        /* code */
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path, const char *method, const char *query_string)
{
    printf("enter cgi\n");
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    buf[0] = 'A';
    buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0)
    {
        while ((numchars > 0) && strcmp("\n", buf))
        {
            numchars = get_line(client, buf, sizeof(buf));
        }
    }
    else{
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf))
        {
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
            {
                content_length = atoi(&(buf[16]));
            }
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1){
            bad_request(client);
            return;
        }
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);

    if (pipe(cgi_output) < 0){
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0){
        cannot_execute(client);
        return;
    }

    if ((pid = fork()) < 0){
        cannot_execute(client);
        return;
    }
    if (pid == 0){
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        dup2(cgi_output[1], 1);
        dup2(cgi_input[0], 0);
        close(cgi_output[0]);
        close(cgi_input[1]);
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0){
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else{
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
        execl(path, path, NULL);
        exit(0);
    }else{
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0)
        {
            for (i = 0; i < content_length; i++){
                recv(client, &c, 1, 0);
                write(cgi_input[1], &c, 1);
            }
        }
        while (read(cgi_output[0], &c, 1) > 0)
        {
            send(client, &c, 1, 0);
        }
        close(cgi_output[0]);
        close(cgi_input[1]);
        waitpid(pid, &status, 0);
    }
}


/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];
    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your borowser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}
/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
    char buf[1024];
    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

int main(void){
    int server_sock = -1;
    uint16_t port = 0;
    int client_sock = -1;
    int costnum = 0;
    struct sockaddr_in client_name;
    socklen_t client_name_len = sizeof(client_name);

    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while(1){
        client_sock = accept(server_sock,
                       (struct sockaddr *)&client_name,
                       &client_name_len);
        costnum++;
        if(client_sock == -1){
            error_die("accept");
        }
        accept_request(client_sock);
        close(client_sock);
    }

    close(server_sock);

    return(0);

}






