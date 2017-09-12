/*
 * util.c
 *
 *  Created on: Nov 3, 2016
 *      Author: root
 */

#include <netdb.h>
#include <sys/socket.h>
#include "util.h"


char calc_bcc_checksum(void *frame, int frame_length)
{
	unsigned char *pbuf = NULL;
	unsigned char checksum = 0x0;
	int i = 0;

	if(NULL==frame || frame_length<=0)
	{
		DEBUG_OUT("frame empty\n");
		return 0xFF;
	}

	pbuf = (unsigned char*)malloc(frame_length);
	if(NULL == pbuf)
	{
		return 0xFF;
	}
	memcpy(pbuf, frame, frame_length);

	for(i=0; i<frame_length; i++)
	{
		checksum ^= (unsigned char)pbuf[i];
	}

	free(pbuf);
	pbuf = NULL;

	return checksum;
}

int check_frame(void *frame, int length)
{
	char *pbuf = NULL;
	int i = 0;
	char checksum = 0;

	if(NULL==frame || length<=0)
	{
		DEBUG_OUT("frame empty\n");
		return -1;
	}

	pbuf = (char*)malloc(length);
	if(NULL == pbuf)
	{
		return 0xFF;
	}
	memset(pbuf, 0x0, length);
	memcpy(pbuf, frame, length);

#ifdef DEBUG
	int idx = 0;
	char buf[22] = {0};
	memcpy(buf,frame, 22);
	for(i=0; i<22; i++)
	{
		printf("0x%02x ", buf[i]);
		if(i%8==7)
		{
			printf("\n");
		}
	}
	printf("\n");
#endif

	for(i=0; i<length; i++)
	{
		checksum ^= pbuf[i];
	}

	free(pbuf);
	pbuf = NULL;

	return checksum;
}

#define CMD_GET_SN	("getprop ro.serialno")
int get_sn_of_device(const char* serial_number)
{
	FILE *fp = NULL;
	char line[32] = {0};


	if(NULL == serial_number)
	{
		return -1;
	}

	fp = popen(CMD_GET_SN, "r");
	if(NULL != fp)
	{
		if(fgets(line, sizeof(line), fp) == NULL)
		{
			pclose(fp);
			return -1;
		}
		line[strlen(line) -1] = '\0';
	}
	pclose(fp);

	strcpy(serial_number, line);

	return 0;
}

#define CMD_GET_VERSION	("getprop ro.build.version.release")
int get_version_of_system(const char* sys_version)
{
	FILE *fp = NULL;
	char line[32] = {0};


	if(NULL == sys_version)
	{
		return -1;
	}

	fp = popen(CMD_GET_VERSION, "r");
	if(NULL != fp)
	{
		if(fgets(line, sizeof(line), fp) == NULL)
		{
			pclose(fp);
			return -1;
		}
		line[strlen(line) -1] = '\0';
	}
	pclose(fp);

	strcpy(sys_version, line);

	return 0;
}

int check_ip_address(const char* addr)
{
	int ret = 1;

	if(NULL == addr)
	{
		return -1;
	}

	char *ptr = addr;
	for(; *ptr!='\0'; ptr++)
	{
		if((isalpha(*ptr)) && (*ptr!='.'))
		{
			ret = 0;
			break;
		}
	}

	return ret;
}

int get_ip_by_domain(const char *domain, char *ip)
{
	struct hostent *host;

	if(NULL==domain || NULL==ip)
	{
		DD("get ip from domain error..\n");
		return -1;
	}

	host = gethostbyname(domain);
	if(NULL == host)
	{
		DD("Couldn't lookup %s:%s\n", domain, hstrerror(h_errno));
		return -1;
	}

	if(host->h_addr_list[0])
	{
		inet_ntop(AF_INET, host->h_addr_list[0], ip, 16);
		return 0;
	}

	return -1;
}


