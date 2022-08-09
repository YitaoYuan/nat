#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#define bufsize 1448

const int server_port = 12345;
const char server_ip[20] = "192.168.22.3"; 
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
 
	// 2. 准备接收方的地址和端口，'192.168.0.107'表示目的ip地址，8266表示目的端口号 
    struct sockaddr_in sock_addr = {0};	
	sock_addr.sin_family = AF_INET;                         // 设置地址族为IPv4
	sock_addr.sin_port = htons(server_port);						// 设置地址的端口号信息
	sock_addr.sin_addr.s_addr = inet_addr(server_ip);	//　设置IP地址
 
    socklen_t addrlen;

    // 3. 发送数据到指定的ip和端口
    while(1)
    {
        puts("send data lenth 1448");
        for(int i = 0; i < bufsize; i++) buf[i] = '1';
        int len = bufsize;
        ret = sendto(sockfd, buf, len, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
        if(ret == -1) {puts("send error"); continue;}
	    ret = recvfrom(sockfd, buf, bufsize, 0, (struct sockaddr*)&sock_addr, &addrlen);
        if(ret == -1) {puts("recv error"); continue;}
        buf[ret] = 0;
        puts(buf);
    }
 
    // 4. 关闭套接字
    close(sockfd);
}
 
