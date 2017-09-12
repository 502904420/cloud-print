/*
 * cmd_header.h
 *
 *  Created on: Nov 2, 2016
 *  	Author: Hekai
 */

#ifndef SERVER_COMM_H_
#define SERVER_COMM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


#define CMD_SERVER_FLAG			0x5AA5
#define CMD_HEADER_LENGTH		20

/*CMD defines*/
#define CMD_SERVER_REQ			100
#define CMD_SERVER_ACK			101
#define CMD_SERVER_ECHO			102
#define CMD_SERVER_PRINTER_INFO	103
#define CMD_SERVER_PRINT_REQ	104
#define CMD_SERVER_PRINT_ACK	105
#define CMD_SERVER_PRINT_RET	106
#define CMD_SERVER_UPDATE_REQ	107
#define CMD_SERVER_UPDATE_ACK	108
#define CMD_SERVER_DISCONNECT	109
#define CMD_SERVER_CFG_REQ		110
#define CMD_SERVER_CFG_ACK		111

#define HEART_BEAT_STAMP		180
#define REPORT_STAMP			300

#define VERSION		"1.1.5"

#pragma pack(push,1)
/*struct defines*/
typedef struct __cmd_header__
{
	unsigned short flag;
	unsigned short length;
	unsigned short type;
	unsigned short version;
	unsigned short cmd;
	unsigned short enc_type;
	unsigned int reserve;
	unsigned int checksum;
}cmd_header_t;

typedef cmd_header_t heart_beat_t;


typedef struct __req_frame__
{
	unsigned char box_sn[32];
	unsigned char version[10];
	unsigned int timestamp;
	unsigned char signature[32];
	unsigned char reverse[32];
	unsigned char sys_ver[32];
}req_frame_t;

#if 0
typedef struct __printer_info__
{
	unsigned char printer_brand[32];
	unsigned char printer_model[32];
	unsigned char printer_sn[32];
	unsigned char printer_mac[20];
}printer_info_t;

typedef struct __printer__
{
	unsigned int printer_type;			//0:usb 1: network 2: com 3: lp
	unsigned char printer_brand[32];
	unsigned char printer_model[32];
	unsigned char unique_flag[32];
	unsigned char printer_ip[16];
	struct __printer__ *next;
}printer_list_t;
#endif

typedef struct __print_req__
{
	unsigned char printer_unique_flag[32];
	unsigned char file_id[32];
	unsigned int file_length;
}print_req_t;

typedef struct __print_ret__
{
	unsigned char file_id[32];
	unsigned char result;
}print_result_t;

typedef struct __update_req__
{
	char version[10];
	unsigned short addr_len;
}update_req_t;

typedef struct __box_cfg__
{
	unsigned short echo_stamp;
	unsigned short check_stamp;
}box_cfg_t;

typedef struct __ack_param__
{
	int sock_fd;
	unsigned short time_stamp;
}ack_param_t;

typedef struct __print_ret_param__
{
	print_req_t print_req;
	int fd;
}print_ret_param;

#pragma pack(pop)


int search_connected_printers();
int send_req_frame_to_server(int fd);
int parse_ack_frame_from_server(int fd);

void init_heart_beat_thread(int fd, short stamp);
void init_report_printer_info(int fd, short stamp);
void init_usb_hotplug_thread(int fd);
void close_heart_beat_proc();
void close_report_printer_proc();
void close_usb_hotplug_proc();


#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMM_H_ */
