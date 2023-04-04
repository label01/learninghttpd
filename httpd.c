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
void send_file_to_client(int, const char *);
void send_response_header(int ,const char *);
void cat(int, FILE *);
void execute_cgi(int, const char *, const char *, const char *);
void bad_request(int);
void cannot_execute(int);
void send_response(int, const char *, const char *, const char *);

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
            send_file_to_client(client_fd, path);
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
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void send_file_to_client(int client_fd, const char *file_path)
{
    //定义缓冲区大小
    const int buf_size = 1024;
    //定义缓冲区
    char buf[buf_size];
    //初始化缓冲区第一个字符
    buf[0] = 'A';
    buf[1] = '\0';

    //跳过请求头
    int numchars = 1;
    while ((numchars > 0) && strcmp("\n", buf) != 0)
    {
        numchars = get_line(client_fd, buf, buf_size);
    }

    //打开文件并发送
    FILE *file = fopen(file_path, "r");
    if (file == NULL)
    {
        not_found(client_fd);
        fprintf(stderr, "Failed to open file %s\n", file_path);
    }
    else{
        //发送响应头
        send_response_header(client_fd, file_path);
        cat(client_fd, file);
    }
    //关闭文件
    fclose(file);
}



/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client_fd, FILE *resource)
{
    /**
     * 声明一个nread变量，用于记录fread函数返回的字节数；
     * 在函数开头对资源文件是否存在的检查，如果资源文件无法打开或读取，则调用not_found函数返回HTTP 404错误
     * 将读取文件的方式从fgets改为fread，这样可以避免读取过程中的换行符，同时也可以读取二进制文件。
     * 在读取文件的循环中，每次读取的字节数由fread函数返回，可以避免因为buf缓冲区大小不够而发生截断现象。
     * 在循环中添加了发送数据到客户端的操作，并在发送失败时打印错误信息。
     * 循环结束后，检查是否在读取文件过程中发生了错误，如果由则打印错误信息。
    */
    char buf[1024]; //缓存区
    //使用size_t，不能表示负数，避免了使用负数或者溢出的风险，提高程序的健壮性和可移植性
    size_t nread = 0; //读取的字节数

    //判断文件是否存在
    if (!resource){
        not_found(client_fd);
        return;
    }
    //循环读取文件内容并发送到客户端
    while ((nread = fread(buf, 1, sizeof(buf), resource)) > 0){
        //判断发送是否成功
        if (send(client_fd, buf, nread, 0) == -1){
            perror("send");
            return;
        }
    }

    //判断读取是否出错
    if (ferror(resource)){
        perror("fread");//出错打印错误信息
        return;
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
/*
*函数名：send_respose
*作用：该函数用于向客户端发送HTTP响应
*参数：
*client_fd:int类型，表示客户端的socket文件描述符
*status:const char*类型，表示HTTP响应状态码，例如“200 OK”
*content_type:const char*类型，表示HTTP响应内容类型，例如“text/html"
*body:const char*类型，表示HTTP响应体，即要返回给客户端的数据
*逻辑：该函数首先根据参数拼接HTTP响应报文的头部信息，包括响应状态码、服务器信息、内容类型等；
*然后将HTTP响应体拼接到头部信息之后，并将整个HTTP响应报文通过客户端的socket文件描述符发送
*给客户端。
*/
/**********************************************************************/
void send_response(int client_fd, const char *status, const char *content_type, const char *body){
    char response[1024];
    //使用snprintf代替sprintf,避免缓冲区溢出
    //snprintf会检查缓冲区剩余空间是否足够存储待写入的数据，保证程序的健壮性
    //这里第二个参数表示缓冲区大小，比原来的1024要小一些，可以根据实际情况调整大小
    snprintf(response, sizeof(response), "HTTP/1.0 %s\r\n", status);
    //使用%s格式化字符串直接将SERVER_STRING添加到response末尾
    /*在这行代码中，第一个参数 response + strlen(response) 的作用是将 response 的指针移动到未被填充的区域的开头。
    在第一次调用 sprintf 后，response 数组中已经包含了响应的状态行和服务器信息。所以我们需要将指针移动到已经填充的区域的末尾，
    以便继续添加响应头和响应体。具体来说，response + strlen(response) 表示 response 数组中已经填充的部分的末尾位置，
    然后 sizeof(response) - strlen(response) 表示未填充的空间的大小，这样保证了后续的写入操作不会越界。
    需要注意的是，由于使用了 sizeof 运算符，因此在使用 snprintf 时，我们不需要手动指定缓冲区的大小，而是可以让编译器根据数组类型自动计算。
    这样可以避免手动计算大小时出现的错误，提高代码的可读性和可维护性。另外，使用 snprintf 而不是 sprintf，可以避免缓冲区溢出导致的安全问题，
    因为 snprintf 会在写入数据时自动检查缓冲区大小，如果溢出则会自动截断。*/
    snprintf(response + strlen(response), sizeof(response) - strlen(response), SERVER_STRING);
    snprintf(response + strlen(response), sizeof(response) - strlen(response), "Content-Type: %s\r\n", content_type);
    snprintf(response + strlen(response), sizeof(response) - strlen(response), "\r\n");
    snprintf(response + strlen(response), sizeof(response) - strlen(response), "%s", body);

    //发送响应
    send(client_fd, response, strlen(response), 0);

}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client_fd)
{
    //返回501 Method Not Implemented响应
    send_response(client_fd, "501 Method Not Implemented", "text/html", "<HTML><HEAD><TITLE>Method Not Implemented\r\n</TITLE></HEAD>\r\n<BODY><P>HTTP request method not supported.\r\n</BODY></HTML>\r\n");
}
/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client_fd){
   //返回404 NOT FOUND响应
   send_response(client_fd, "404 NOT FOUND", "text/html", "<HTML><HEAD><TITLE>NOT Found</TITLE></HEAD>\r\n<BODY><P>The server could not fulfill your request because the resource specified is unavailable or nonexistent.\r\n</BODY></HTML>\r\n");
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void send_response_header(int client_fd, const char *file_path)
{
    (void)file_path;
    //发牛200 OK响应
    send_response(client_fd, "200 OK", "text/html", "");
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client_fd)
{
    //返回400 BAD REQUEST响应
    send_response(client_fd, "400 BAD REQUEST", "text/html", "<P>Your browser sent a bad request, such as a POST without a Content-Length.\r\n");

}
/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client_fd)
{
    //返回500 Internal Server Error 响应
    send_response(client_fd, "500 Internal Server Error", "text/html", "<P>Error prohibited CGI execution.\r\n");
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






