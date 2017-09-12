/*
 * broadcast.h
 *
 *  Created on: Nov 2, 2016
 *      Author: root
 */

#ifndef APP_COMM_H_
#define APP_COMM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BCST_PORT	8888

#define CMD_APP_BROADCAST		100
#define CMD_APP_SEND_SN			101

#define BCST_FRAME_FLAG				(0x5AA4)
#define BCST_REQ_FRAME_LEN			22
#define BCST_ACK_FRAME_LEN			52

#pragma pack(push,1)
typedef struct __bcst_req_frame__
{
	short flag;
	short length;
	short type;
	short version;
	short cmd;
	short enc_type;
	int reserve;
	int checksum;
	short port;
}bcst_req_frame_t;

typedef struct __bcst_ack_frame__
{
	short flag;
	short length;
	short type;
	short version;
	short cmd;
	short enc_type;
	int reserve;
	int checksum;
	char sn[32];
}bcst_ack_frame_t;
#pragma pack(pop)


int send_sn_to_app();

#endif /* APP_COMM_H_ */
