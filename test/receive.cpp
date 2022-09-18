#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
 
#define bufsize 1024

const int server_port = 12345;
const char server_ip[20] = "192.168.2.3"; 
char buf[bufsize + 1];

int main(void)
{
	int ret = -1;
	// 1、使用socket()函数获取一个socket文件描述符
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (-1 == sockfd)
	{
		printf("socket open err.");
		return -1;
	}
 
    // 2、绑定本地的相关信息，如果不绑定，则系统会随机分配一个端口号
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;                                //使用IPv4地址
    local_addr.sin_addr.s_addr = inet_addr(server_ip);        //本机IP地址
    local_addr.sin_port = htons(server_port);                             //端口
    bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));//将套接字和IP、端口绑定
 
    // 3、等待接收对方发送的数据
    struct sockaddr_in recv_addr;
    socklen_t addrlen = sizeof(recv_addr);
    
    while(1) {
        ret = recvfrom(sockfd, buf, bufsize, 0,(struct sockaddr*)&recv_addr,&addrlen);  //1024表示本次接收的最大字节数
        if(ret == -1) {puts("recv error"); continue;}
        buf[ret] = 0;
        printf("[recv from %s:%d]:",inet_ntoa(*(struct in_addr*)&recv_addr.sin_addr.s_addr),ntohs(recv_addr.sin_port));
        puts(buf);
        ret = sendto(sockfd, buf, ret, 0, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
        if(ret == -1) {puts("send error"); continue;}
    }
    
    // 4. 关闭套接字
    close(sockfd);
}
