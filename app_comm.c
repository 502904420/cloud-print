/*
 * broadcast.c
 *
 *  Created on: Nov 2, 2016
 *      Author: root
 */

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "util.h"
#include "app_comm.h"


static int connect_to_app(char* ip, int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
	{
		DEBUG_OUT("socket create error when connet to app\n");
		return -1;
	}

	struct sockaddr_in app_addr;
	memset(&app_addr, 0x0, sizeof(app_addr));
	app_addr.sin_family = AF_INET;
	app_addr.sin_addr.s_addr = inet_addr(ip);
	app_addr.sin_port = htons(port);

	int result = connect(fd, (struct sockaddr *)&app_addr, sizeof(struct sockaddr));
	if(result < 0)
	{
		printf("Can not connect to app, %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}


static void pack_frame(bcst_ack_frame_t *frame, char* sn)
{
	bcst_ack_frame_t bcst_ack_frame;
	memset(&bcst_ack_frame, 0x0, sizeof(bcst_ack_frame_t));

	if(NULL==sn || NULL==frame)
	{
		return;
	}

	bcst_ack_frame.flag = BCST_FRAME_FLAG;
	bcst_ack_frame.length = BCST_ACK_FRAME_LEN;
	bcst_ack_frame.type = 1;
	bcst_ack_frame.version = 1;
	bcst_ack_frame.cmd = CMD_APP_SEND_SN;
	bcst_ack_frame.enc_type = 0;
	memcpy(bcst_ack_frame.sn, sn, strlen(sn));

	char checksum = calc_bcc_checksum((void*)&bcst_ack_frame, BCST_ACK_FRAME_LEN);
	bcst_ack_frame.checksum = checksum;

	memcpy(frame, &bcst_ack_frame, sizeof(bcst_ack_frame));

	return;
}


static int query_app_linten_port(const bcst_req_frame_t* frame)
{
	char tmp_buf[BCST_REQ_FRAME_LEN] = {0};
	char checksum = 0xFF;
	int port = 0;

	if(NULL == frame)
	{
		return -1;
	}

#ifdef DEBUG
	int i = 0;
	char buf[BCST_REQ_FRAME_LEN] = {0};
	memcpy(buf,frame, BCST_REQ_FRAME_LEN);
	for(i=0; i<BCST_REQ_FRAME_LEN; i++)
	{
		printf("0x%02x ", buf[i]);
		if(i%8==7)
		{
			printf("\n");
		}
	}
	printf("\n");
#endif


	if(frame->flag != BCST_FRAME_FLAG &&
			frame->cmd != CMD_APP_BROADCAST &&
			frame->version != 1 &&
			frame->length != BCST_REQ_FRAME_LEN &&
			frame->type != 1)
	{
		DEBUG_OUT("broadcast frame parse error\n");
		return -1;
	}

	checksum = check_frame((void*)frame, BCST_REQ_FRAME_LEN);
	if (checksum != 0)
	{
		DEBUG_OUT("broadcast frame checksum error\n");
		return -1;
	}

	return frame->port;
}

int send_sn_to_app()
{
	int fd;
	char last_app_ip[16] = {0};
	bcst_req_frame_t bcst_req_frame;
	bcst_ack_frame_t bcst_ack_frame;
	struct sockaddr_in bcst_addr, local_addr;

	memset(&bcst_req_frame, 0x0, sizeof(bcst_req_frame));
	memset(&bcst_ack_frame, 0x0, sizeof(bcst_ack_frame));

	memset(&bcst_addr, 0x0, sizeof(bcst_addr));
	memset(&local_addr, 0x0, sizeof(local_addr));

	int ret = -1;
#ifdef BOX
	char sn[32];
	memset(sn, 0x0, 32);
	ret = get_sn_of_device(sn);
	if(ret < 0)
	{
		DEBUG_OUT("get sn error\n");
		return -1;
	}
	pack_frame(&bcst_ack_frame, sn);
#else
	pack_frame(&bcst_ack_frame, "123456789abce");
#endif

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		DEBUG_OUT("create socket failed\n");
		return -1;
	}

	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(BCST_PORT);

	ret = bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr));
	if(ret < 0)
	{
		DEBUG_OUT("bind failed:%s\n", strerror(errno));
		close(fd);
		return -1;
	}

	socklen_t addr_len = sizeof(struct sockaddr);

	while(1)
	{
		DEBUG_OUT("Wait to broadcast from app...\n");
		int recv_count = recvfrom(fd, &bcst_req_frame, sizeof(bcst_req_frame), 0, (struct sockaddr*)&bcst_addr, &addr_len);
		if(recv_count != sizeof(bcst_req_frame))
		{
			memset(&bcst_req_frame, 0x0, sizeof(bcst_req_frame));
			DEBUG_OUT("noting recv \n");
			continue;
		}

		DEBUG_OUT("APP_COMM:recv broadcast info OK\n");
		//parse frame to get app ip and port
		int app_port = query_app_linten_port(&bcst_req_frame);
		if(app_port<=0 || app_port>=65535)
		{
			DEBUG_OUT("query app port error\n");
			memset(&bcst_req_frame, 0x0, sizeof(bcst_req_frame));
			continue;
		}

		//connect to app
		DEBUG_OUT("app ip is %s, port is %d\n", inet_ntoa(bcst_addr.sin_addr), app_port);
		int app_fd = connect_to_app(inet_ntoa(bcst_addr.sin_addr), app_port);
		if(app_fd < 0)
		{
			DEBUG_OUT("connect to app error\n");
			memset(&bcst_req_frame, 0x0, sizeof(bcst_req_frame));
			continue;
		}
		//send sn to app
		int send_count = send(app_fd, (void*)&bcst_ack_frame, sizeof(bcst_ack_frame), 0);
		if(send_count != sizeof(bcst_ack_frame))
		{
			DEBUG_OUT("send frame failed, count=%d\n", send_count);
			close(app_fd);
			continue;
		}

		DEBUG_OUT("send frame OK!\n");
		//close connect with app
		close(app_fd);

	}

	return 0;
}
