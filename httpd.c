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
    // 定义变量
    char request[MAX_REQUEST_SIZE];
    //初始化request字符串
    memset(request, 0, MAX_REQUEST_SIZE);
    
    //从客户端读取请求
    ssize_t request_len = get_line(client_fd, request, sizeof(request));
    if (request_len < 0){
        perror("Failed to receive request\n");
        return;
    }
    //初始化method、url、path字符串
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL_SIZE];
    char path[MAX_PATH_SIZE];

    memset(method, 0, MAX_METHOD_SIZE);
    memset(url, 0, MAX_URL_SIZE);
    memset(path, 0, MAX_PATH_SIZE);

    size_t i, j;
    struct stat st;
    /*becomes true if server decides this is a CGI program*/
    int cgi = 0;//标识是否为CGI程序，默认为0
    char *query_string = NULL;// 存储查询字符串的指针
    i = 0;
    j = 0;
    //读取请求方法
    while(!ISspace(request[j]) && ( i < sizeof(method) - 1))
    {
        method[i] = request[j];
        i++;
        j++;
    }
    method[i] = '\0';
    //printf("the method is %s\n", method);
    //如果不是GET或POST方法
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client_fd); // 发送501未实现错误给客户端
        return;
    }

    if (strcasecmp(method, "POST") == 0)
    {
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
    //处理查询字符，如果是GET方法
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        //定位到字符串末尾
        while (*query_string != '\0'){
            query_string++;
        }
        //找到查询字符串的起始位置
        while ((*query_string != '?') && (*query_string != '\0'))
        {
            query_string++;
        }
        //如果找到了查询字符串
        if (*query_string == '?')
        {
            //printf("enter GET, the cgi = 1\n");
            cgi = 1; //标识为CGI程序
            *query_string = '\0';  //将？字符替换为字符结束符
            query_string++;//指向查询字符串
        }
        
    }
    sprintf(path, "htdocs%s", url); //拼接文件路径
    //printf("the sprintf string is  %s\n", path);
    //如果路径最后一个字符是'/'， 则默认请求的是该目录下的index.html文件
    if (path[strlen(path) -1] == '/')
    {
        strcat(path, "index.html");
    }
    //如果文件不存在
    if (stat(path, &st) == -1){
        //跳过请求头
        /**
        *这段代码中，如果文件不存在，程序会跳过请求头，是为了防止在发送404页面之前
        *客户端可能已经发送了一些请求数据（例如POST请求的数据），而这些数据并不应该
        *被处理。因此， 这里先通过while循环读取请求头中的每一行，直到读取到一个空行
        *（表示请求头结束），或者读取到了所有的请求头，这样可以确保在发送404页面之前，
        *已经读取并清除了客户端发送的请求数据。
        *
        *只有当请求头读取完毕，服务器才能够准确地发送404页面，而不会把客户端地请求数据
        *也一并发送过去。
        */
        while ((request_len > 0) && strcmp("\n", request))
        {
            request_len = get_line(client_fd, request, sizeof(request));
        }
        //返回404错误页面
        not_found(client_fd);
    }
    else{
        //如果请求的是目录的话，则打开该目录下的index.html文件
        if ((st.st_mode & S_IFMT) == S_IFDIR)
        {
            strcat(path, "/index.html");
        }
        //判断文件是否可执行，若是则为CGI程序，需要执行
        if ((st.st_mode & S_IXUSR) || 
            (st.st_mode & S_IXGRP) ||
            (st.st_mode & S_IXOTH) )
        {
            cgi = 1;
        }
        //如果不是cgi程序,将文件内容返回给客户端
        if (!cgi)
        {
            send_file_to_client(client_fd, path);
        }
        //如果是CGI程序，执行该程序并将结果返回给客户端
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
/*
                                +--------+         +--------+
                                | parent |         |  child |
                                +--------+         +--------+
                                    |                   |
                                    |                   |
                                    |                   |
+-------------+     data     +-------------+     data     +-------------+
| client data | ----------> | parent pipe | ----------> | child pipe  |
+-------------+             +-------------+             +-------------+
                                    |                   |
                                    |                   |
                                    |                   |
+-------------+     output   +-------------+     input    +-------------+
|  child out  | <---------- | parent pipe | <---------- |  child in  |
+-------------+             +-------------+             +-------------+
                                    |                   |
                                    |                   |
                                    |                   |
                                +--------+         +--------+
                                | parent |         |  child |
                                +--------+         +--------+
*/
/**********************************************************************/
void execute_cgi(int client_fd, const char *path, const char *method, const char *query_string)
{
    char buf[1024]; 
    int cgi_output[2]; //cgi脚本标准输出管道
    int cgi_input[2]; //cgi脚本标准输入管道
    pid_t pid; //进程ID
    int status;//状态码
    int loop_index;//用于循环计数的索引
    char current_char;//用于读取或发送单个字符
    int num_char = 1;//用于存储或读取每次发送的字节数
    int content_length = -1; //请求体长度

    //保证buf数组非空
    buf[0] = 'A';
    //初始化buf数组
    buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0)
    {
        while ((num_char > 0) && strcmp("\n", buf))
        {
            num_char = get_line(client_fd, buf, sizeof(buf));
        }
    }
    else{
        num_char = get_line(client_fd, buf, sizeof(buf));
        //strcmp 函数会将两个字符串逐个字符地比较，若在某个位置两个字符不同，
        //就会根据这个位置上两个字符的 ASCII 码值大小关系返回一个负数或正数，若两个字符串完全相同，
        //则返回 0。因此，只要传入的两个字符串在某一位置上的字符不相同，strcmp 就会返回大于零的值。
        while ((num_char > 0) && strcmp("\n", buf))
        {
            //之所以将buf数组中的第16个元素设置为'\0',就是为了去除HTTP请求头"Content-Length:"
            //后面跟着的空白字符,从而方便提取Content-Length的值.因为这些字符可能会影响atoi函数的解析结果.
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
            {
                content_length = atoi(&(buf[16]));
            }

            num_char = get_line(client_fd, buf, sizeof(buf));
        }
        if (content_length == -1){
            bad_request(client_fd);
            return;
        }
    }
    send_response(client_fd, "200 OK", "text/html", "");
    //创建两个管道,用于父进程和子进程间通信
    /**
     * pipe()是一个用于创建管道的系统调用。它创建了一个无名管道，该管道是一个半双工
     * 的通信通道，其中的数据只能在一个方向上传输。
     * 他的参数包含两个int类型的数组，其中pipefd[0]用于读取管道，pipefd[1]用于写入管道；
     * 
    */
    if (pipe(cgi_output) < 0 || pipe(cgi_input) < 0){
        cannot_execute(client_fd);
        return;
    }
     /**
     * 当我们创建一个子进程时，它会继承父进程的所有打开的文件描述符，包括管道。
     * 所以在下述代码中，我们创建了两个管道，一个用于父进程向子进程传递
     * 数据，另一个用于子进程向父进程传递数据。
    */
    if ((pid = fork()) < 0){
        cannot_execute(client_fd);
        return;
    }
    //子进程
    if (pid == 0){
        //定义环境变量字符串
        // char meth_env[255];
        // char query_env[255];
        // char length_env[255];

        //重定义管道读写端
        /*子进程执行的CGI程序需要读取父进程传递过来的数据，
        而父进程将数据写入到管道中的写端，子进程只需从管道的读端（'cgi_input[0]'）
        中读取即可。通过重定向标准输入（STDIN_FILENO），子进程可以将从管道读取的数据
        作为标准输入，这样CGI程序在读取标准输入时实际上就读取了从管道中传递过来的数据。
        换言之，子进程在读取标准输入时，实际上就是在读取管道的读端。
        */
        dup2(cgi_output[1], STDOUT_FILENO);
        dup2(cgi_input[0], STDIN_FILENO);
        //关闭无用的管道
        close(cgi_output[0]);
        close(cgi_input[1]);
        //设置环境变量，便于CGI程序获取请求信息
        
        //原程序，使用setenv函数替换putenv函数可以提高代码的可读性和安全性
        //setenv函数会检查传入的环境变量和值的长度，可以更加安全地设置环境变量
        /*sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);*/
        setenv("REQUEST_METHOD", method, 1);
        if (strcasecmp(method, "GET") == 0){
            //原程序使用sprintf方法拼接后的字符串，可能回包含特殊字符，例如空格
            //和换行符，这可能导致在处理环境变量的时候出现问题。而setenv函数可以直接
            //设置键值对，不需要通过字符串拼接，因此可以避免这些问题。此外，putenv的缺陷
            //是存在相同变量名时会覆盖原来的值，而 setenv可以设置标志位来控制是否覆盖原来的值，
            //我们这里标志位设为1，会覆盖掉原来的值
            /*sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);*/
            setenv("QUERY_STRING", query_string, 1);
        }
        else{
            // sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            // putenv(length_env);
            /**
             * 这里说一下，这里和前面修改的不同之处，为什么要加一个content_length_str变量，因为content_length
             * 不能直接作为环境变量的值。环境变量的值必须是字符串类型。所以用snprintf对content_length_str进行赋值；
             * 此外snprintf函数会将指定格式的字符串输出到缓冲区中，如果缓冲区有值，则会被覆盖，所以可以不用对
             * content_length_str进行初始化。同时还可以避免缓冲区溢出的风险。
            */
            char content_length_str[32];
            snprintf(content_length_str, sizeof(content_length_str), "%d", content_length);
            setenv("CONTENT_LENGTH", content_length_str, 1);
        }
        //在子进程中执行CGI程序
        execl(path, path, NULL);
        exit(0);
    }else{
        //父进程
        //关闭无用的管道
        /**
         * 在管道通信中，父进程和子进程通过管道进行通信。本质上时一种单向通信机制，
         * 记住是单向通信机制，所以父进程只能往管道写数据，而子进程只能从管道读取数据。
         * 为了实现双向通信，需要重新定义子进程的读写端。具体来说，就是父进程需要关闭
         * 子进程的写端，子进程需要关闭父进程的读端。这样保证了父进程只能从管道中
         * 读取数据，而子进程只能往管道中写数据。这样就实现了双向通信。
         * 
        */
        close(cgi_output[1]);
        close(cgi_input[0]);
        char request_str[1024];
        //如果POST请求，读取请求体并写入管道
        if (strcasecmp(method, "POST") == 0)
        {
            for (loop_index = 0; loop_index < content_length; loop_index++){
                if (recv(client_fd, &current_char, 1, 0) < 1){
                    break;
                }
                if (write(cgi_input[1], &current_char, 1) < 1){
                    break;
                }
                request_str[loop_index] = current_char;
            }
            //读取客户端请求并打印
            request_str[loop_index] = '\0';
            printf("client request string: %s\n", request_str);
        }
        // 从管道读取CGI程序的输出， 并发送给客户端
        while (read(cgi_output[0], &current_char, 1) > 0)
        {
            if(send(client_fd, &current_char, 1, 0) < 1){
                break;
            }
        }
        //关闭管道
        close(cgi_output[0]);
        close(cgi_input[1]);
        //等待子进程结束，避免出现僵尸进程
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
    int server_sock = -1; //服务器套接字描述符
    uint16_t port = 0; //监听的端口号
    int client_sock = -1; //客户端套接字描述符
    int costnum = 0; //连接的客户端数量
    struct sockaddr_in client_name; //客户端信息结构体
    socklen_t client_name_len = sizeof(client_name); //客户端信息结构体大小

    server_sock = startup(&port); // 创建套接字， 绑定端口
    printf("httpd running on port %d\n", port); // 打印服务器信息

    while(1){ //服务器一直运行
        client_sock = accept(server_sock,
                       (struct sockaddr *)&client_name,
                       &client_name_len); //接受客户端连接
        costnum++;//记录连接客户端的数量
        if(client_sock == -1){ //如果连接失败，输出错误信息
            error_die("accept");
        }
        accept_request(client_sock); //处理客户端请求
        close(client_sock); //关闭客户端套接字
    }

    close(server_sock); // 关闭服务器套接字

    return(0);

}






