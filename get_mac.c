/*
 * get-mac.c
 *
 *  Created on: Dec 30, 2016
 *      Author: root
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>

#include "util.h"

#define MAX_MAC_LEN 	24
#define COMPART_MAC 	":"
#define MAX_BUF_LEN 	128
#define LOCAL_IP		"0.0.0.0"
#define NIC_NAME		"eth0"
#define PAD_MAC	"00:00:00:00:00:00"
#define BRD_MAC	"FF:FF:FF:FF:FF:FF"
#define ARP_SEND_COUNT 3
#define RX_ARP_COUNT 3
#define SLEEP_MAX_US	(1000 * 100)
#define PAD_LEN 18

static void set_ip_addr(char* buf, char* str);
static void set_hw_addr(char* buf, char *str);
static char* get_local_mac();

#pragma pack(push,1)
struct ether_header
{
	unsigned char ether_dhost[6];
	unsigned char ether_shost[6];
	unsigned short ether_type;
};

struct arp_header
{
	unsigned short ar_hrd;
	unsigned short ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short ar_op;
	unsigned char __ar_sha[6];
	unsigned char __ar_sip[4];
	unsigned char __ar_tha[6];
	unsigned char __ar_tip[4];
};

struct arp_packet
{
	struct ether_header ethhdr;
	struct arp_header arphdr;
	unsigned char padding[18];
};
#pragma pack(pop)

#define FRAME_TYPE      0x0806                  /* arp=0x0806,rarp=0x8035 */
#define HARD_TYPE       1                       /* ethernet is 1 */
#define PROTO_TYPE      0x0800                  /* IP is 0x0800 */
#define OP_CODE         1                       /* arp=1/2,1为请求，2为应答,rarp=3/4 */

char *get_mac_by_ip(char* dst_ip)
{
	int sock_fd;
	struct arp_packet arp;
	struct arp_packet arp_res;
	struct sockaddr sa;

	unsigned int str_len = 0;
	unsigned int offset = 0;
	int i;
	int s;

	if(NULL == dst_ip)
	{
		DEBUG_OUT("dst ip is NULL\n");
		return NULL;
	}

	memset(&arp, 0x0, sizeof(arp));
	memset(&arp_res, 0x0, sizeof(arp_res));

	char* local_mac = get_local_mac();
	if (NULL==local_mac)
	{
		DEBUG_OUT("get local MAC fail\n");
		return NULL;
	}
	if(0==strcmp(local_mac, ""))
	{
		DEBUG_OUT("local mac is empty\n");
		free(local_mac);
		return NULL;
	}

	//sock_fd = socket(AF_INET, SOCK_PACKET, htons(FRAME_TYPE));
	sock_fd = socket(AF_INET, SOCK_RAW, htons(FRAME_TYPE));
	if(sock_fd < 0)
	{
		free(local_mac);
		return NULL;
	}

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100;
	if(setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		DEBUG_OUT("set socket timeout OK!\n");
	}
	//pack ARP packet
	arp.ethhdr.ether_type = htons(FRAME_TYPE);
	set_hw_addr(arp.ethhdr.ether_dhost, BRD_MAC);
	set_hw_addr(arp.ethhdr.ether_shost, local_mac);
	arp.arphdr.ar_hrd = htons(HARD_TYPE);
	arp.arphdr.ar_pro = htons(PROTO_TYPE);
	arp.arphdr.ar_op = htons(OP_CODE);
	arp.arphdr.ar_hln = (unsigned int)(6);
	arp.arphdr.ar_pln = (unsigned int)(4);

	set_hw_addr((char*)arp.arphdr.__ar_tha, BRD_MAC);
	set_hw_addr((char*)arp.arphdr.__ar_sha, local_mac);
	set_ip_addr((char*)arp.arphdr.__ar_tip, dst_ip);
	set_ip_addr((char*)arp.arphdr.__ar_sip, LOCAL_IP);
	bzero(arp.padding, PAD_LEN);

	memset(&sa, 0x0, sizeof(sa));
	strcpy(sa.sa_data, NIC_NAME);

	//send arp packet
	int send_count = ARP_SEND_COUNT;
	int recv_bytes = 0;
	char target_mac[MAX_MAC_LEN] = {0};
	char target_ip[MAX_MAC_LEN] = {0};
	while(send_count--)
	{
		if(sendto(sock_fd, &arp, sizeof(arp), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		{
			printf("send arp packet error:%s\n", strerror(errno));
			free(local_mac);
			return NULL;
		}
		//recv arp ack
		int try_count = RX_ARP_COUNT;
		int addr_len = sizeof(sa);
		do
		{
			usleep(SLEEP_MAX_US);
			recv_bytes = recvfrom(sock_fd, &arp_res, sizeof(arp_res), 0, (struct sockaddr*)&sa, (socklen_t*)&addr_len);

			if(recv_bytes >= 60 && 2 == ntohs(arp_res.arphdr.ar_op))
			{
				char buff[MAX_MAC_LEN] = {0};
				offset = 0;
				for(s=0; s<4; s++)
				{
					memset(buff, 0x0, sizeof(buff));
					sprintf((char*)buff, "%d", (unsigned char)arp_res.arphdr.__ar_sip[s]);

					str_len = strlen(buff);
					memcpy(target_ip + offset, buff, str_len);
					offset += str_len;
					if(s<3)
					{
						memset(buff, 0x0, sizeof(buff));
						sprintf((char*)buff, "%s", ".");
						str_len = 1;
						memcpy(target_ip + offset, buff, str_len);
						offset += str_len;
					}
				}
				if(!strcmp(target_ip, dst_ip))
				{
					//g_find_ip_flag = 1;
					goto analyse_arp_response;
				}
			}
		}while(try_count--);
	}
analyse_arp_response:
	if(recv_bytes == -1)
	{
		close(sock_fd);
		free(local_mac);
		return NULL;
	}

	char chBuff[MAX_MAC_LEN];
#if 0
	memset(chBuff, 0x00, sizeof(chBuff));
	// format ip
	offset = 0;
	for (s = 0; s < 4; s++)
	{
		memset(chBuff, 0x00, sizeof(chBuff));
		sprintf( (char *)chBuff, "%d", (unsigned char)arp_res.arphdr.__ar_sip[s]);
		//strTarIP += chBuff;
		str_len = strlen(chBuff);
		memcpy(g_target_ip + offset, chBuff, str_len);
		offset += str_len;
		if (s < 3)
		{
			memset(chBuff, 0x00, sizeof(chBuff));
			sprintf( (char *)chBuff, "%s", ".");
			//strTarIP += chBuff;
			str_len = strlen(chBuff);
			memcpy(g_target_ip + offset, chBuff, str_len);
			offset += str_len;
		}
	}
#endif
	//format MAC
	memset(chBuff, 0x00, sizeof(chBuff));
	offset = 0;
	for (s = 0; s < 6; s++)
	{
		memset(chBuff, 0x00, sizeof(chBuff));
		sprintf( (char *)chBuff, "%02X", (unsigned char)arp_res.arphdr.__ar_sha[s]);
		//strTarMAC += chBuff;
		str_len = strlen(chBuff);
		memcpy(target_mac+offset, chBuff, str_len);
		offset += str_len;
		if (s < 5)
		{
			memset(chBuff, 0x00, sizeof(chBuff));
			sprintf( (char *)chBuff, "%s", COMPART_MAC);
			//strTarMAC += chBuff;
			str_len = strlen(chBuff);
			memcpy(target_mac+offset, chBuff, str_len);
			offset += str_len;
		}
	}
	close(sock_fd);

	char *dst_mac = (char*)malloc(MAX_MAC_LEN);
	if(NULL == dst_mac)
	{
		DEBUG_OUT("malloc faile when get dst mac\n");
		free(local_mac);
		return NULL;
	}
	strcpy(dst_mac, target_mac);
	free(local_mac);

	return dst_mac;
}

static char *get_local_mac()
{
	int fd;
	int idx;
	char buff[MAX_MAC_LEN] = {0};
	unsigned int len = 0;
	unsigned offset = 0;
	struct ifreq ifreq_buf;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		printf("Error: Create socket failed\n");
		return "";
	}

	memset(&ifreq_buf, 0x0, sizeof(ifreq_buf));
	strcpy(ifreq_buf.ifr_ifrn.ifrn_name, "eth0");
	if(-1 == ioctl(fd, SIOCGIFHWADDR, &ifreq_buf))
	{
		printf("Error:get interface failed\n");
		return "";
	}
	close(fd);

	char *local_mac = (char*)malloc(MAX_MAC_LEN);
	if(NULL == local_mac)
	{
		DD("malloc failed when get local mac\n");
		return "";
	}

	offset = 0;
	for (idx=0; idx<6; idx++)
	{
		memset(buff, 0x0, sizeof(buff));
		sprintf(buff, "%.2X", (unsigned char)ifreq_buf.ifr_ifru.ifru_hwaddr.sa_data[idx]);
		len = strlen(buff);
		memcpy(local_mac + offset, buff, len);
		offset += len;
		if(idx < 5)
		{
			memset(buff, 0x0, sizeof(buff));
			sprintf(buff, "%s", COMPART_MAC);
			len = strlen(buff);
			memcpy(local_mac + offset, buff, len);
			offset += len;
		}
	}
	DEBUG_OUT("local mac is %s\n", local_mac);

	return local_mac;
}

static void set_hw_addr(char buf[], char *str)
{
	int i;
	char c, val;
	for(i=0; i<6; i++)
	{
		if(!(c = tolower(*str++)))
		{
			printf("Invalid hardware address\n");
			exit(1);
		}
		if(isdigit(c))
		{
			val = c - '0';
		}
		else if (c>='a' && c<='f')
		{
			val = c - 'a'+ 10;
		}
		else
		{
			printf("Invalid hardware address\n");
			exit(1);
		}

		buf[i] = val << 4;
		if(!(c = tolower(*str++)))
		{
			printf("Invalid hardware address\n");
			exit(1);
		}
		if(isdigit(c))
		{
			val = c - '0';
		}
		else if (c>='a' && c<='f')
		{
			val = c - 'a'+ 10;
		}
		else
		{
			printf("Invalid hardware address\n");
			exit(1);
		}

		buf[i] |= val;
		if(*str == ':')
		{
			str++;
		}
	}

	return;
}

static void set_ip_addr(char* buf, char* str)
{
	struct in_addr addr;
	memset(&addr, 0x0, sizeof(addr));
	addr.s_addr = inet_addr(str);
	memcpy(buf, &addr, 4);

	return;
}


#if 0
int main(int argc, char *argv[])
{
	char *mac = NULL;
	if(argc == 2)
	{
		mac = get_mac_by_ip(argv[1]);
	}
	else
	{
		printf("Usage: %s dst_ip\n", argv[0]);
		return -1;
	}

	if(NULL == mac)
	{
		printf("get mac failed\n");
		return -1;
	}

	printf("remote mac is %s\n", mac);
	free(mac);

	return 0;
}
#endif













