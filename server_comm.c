/*
 * server_comm.c
 *
 *  Created on: Nov 3, 2016
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
//#include <linux/types.h>
//#include <linux/netlink.h>
#include <arpa/inet.h>
#include <time.h>
#include <regex.h>
#include <fcntl.h>

#include <event.h>
#include <event2/util.h>
#include <libusb-1.0/libusb.h>
#include <usb-printer.h>
#include <net-printer.h>

#include "util.h"
#include "md5.h"
#include "databuffer.h"
#include "server_comm.h"
#include "http_load.h"
#include "printer.h"



#define COMM_KEY	"06dbe5be4da6468eae8ac8a0f00cee31"
#define PRINT_DOC		"/data/"
#define DOWNLOAD_FILE	"/data/print-server"

#define USB_PRINTER		"usb"
#define NET_PRINTER		"socket"

static int g_report_stamp = 0;
static struct event_base *g_heartbeat_base = NULL;
static struct event *g_heartbeat_event = NULL;
static struct event_base *g_reporter_base = NULL;
static struct event *g_reporter_event = NULL;
static libusb_hotplug_callback_handle g_hotplug_handle;
static int exit_hotplug = 1;
static int exit_parse = 1;
//static int report_state=1;
static int g_working_printers=0;

static pthread_mutex_t g_search_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_search_cond = PTHREAD_COND_INITIALIZER;
static int g_report_state = 0;

static pthread_mutex_t g_print_mutex = PTHREAD_MUTEX_INITIALIZER;

//----------------------search printer list-------------------------------//
static int pack_printer_info_frame(char* buf)
{
	cmd_header_t cmd_header;
	char* printer_info_buf = NULL;
	int printer_count = 0;
	int frame_len = 0;
	char *ptr = NULL;

	if(NULL == buf)
	{
		ASSERT(buf!=NULL, "input buffer failed when pack printer info frame");
		return -1;
	}
	memset(&cmd_header, 0x0, sizeof(cmd_header));
	printer_count = get_printer_count();
	printer_info_buf = (char*)malloc(sizeof(printer_info_t) * printer_count);
	serialize_printer_list(printer_info_buf);

	frame_len = sizeof(cmd_header_t)+sizeof(int)
			+sizeof(printer_info_t)*printer_count;
	ptr = (char*)malloc(frame_len);
	if(NULL == ptr)
	{
		ASSERT(ptr!=NULL, "malloc failed when pack printer info frame");
		return -1;
	}
	memset(ptr, 0x0, frame_len);

	//pack header
	cmd_header.flag = SWAP16(CMD_SERVER_FLAG);
	cmd_header.length = SWAP16(frame_len);
	cmd_header.type = SWAP16(1);
	cmd_header.version = SWAP16(1);
	cmd_header.cmd = SWAP16(CMD_SERVER_PRINTER_INFO);
	cmd_header.enc_type = 0;
	cmd_header.checksum = 0;

	//pack frame : cmd_header + printer_count + printer1_info + printer2_info + ...
	memcpy(ptr, &cmd_header, sizeof(cmd_header));
	int tmp = SWAP32(printer_count);

	memcpy(ptr+sizeof(cmd_header), &tmp, sizeof(int));
	memcpy(ptr+sizeof(cmd_header)+sizeof(int), printer_info_buf, sizeof(printer_info_t)*printer_count);
	//overwrite cmd_header
	char checksum = calc_bcc_checksum(ptr, frame_len);
	cmd_header.checksum = SWAP32(checksum);
	memcpy(ptr, &cmd_header, sizeof(cmd_header));
	memcpy(buf, ptr, frame_len);

	free(ptr);
	free(printer_info_buf);

	return frame_len;
}

int send_printer_info_to_server(int fd)
{
	char* frame = NULL;
	int send_len = 0;

	frame = (char*)malloc(1024);
	int frame_len = pack_printer_info_frame(frame);
	ASSERT(frame!=NULL, "get frame error!!!!\n");
#if 0
	DEBUG_OUT("***********************************************\n");
	int i = 0;
	char tmp_buf[68] = {0};
	memcpy(tmp_buf, frame, 20);
	for(i=0; i<20; i++)
	{
		printf("0x%02x ", (unsigned char)tmp_buf[i]);
		if(i%8==7)
		{
			printf("\n");
		}
	}
	printf("\n");
	DEBUG_OUT("**********************************************\n");
#endif
	if(fd < 0)
	{
		ASSERT(fd>0, "send printer info to server error\n");
		return -1;
	}
	send_len = write(fd, frame, frame_len);

	free(frame);

	return send_len;
}

int search_connected_printers()
{
	clear_printer_list();
	DEBUG_OUT("printer count is %d\n", get_printer_count());
	search_network_printer(parse_uri_and_add_printer);
	usleep(100);
	search_usb_printer(parse_uri_and_add_printer);
	DEBUG_OUT("printer count is %d after search\n", get_printer_count());
	return 0;
}

void report_printer_proc(int fd, short event, void *arg)
{
	int size = 0;
	char buf[2048] = {0};

	if(NULL==arg || fd<0)
	{
		return;
	}
#if 0
	if(report_state)
	{
		int ret = pthread_mutex_trylock(&g_search_mutex);
		if(ret != 0)
		{
			DEBUG_OUT("search printer locked when report\n");
			return;
		}
		DEBUG_OUT("Search connected printers...\n");
		search_connected_printers();
		int send_count = send_printer_info_to_server(fd);
		g_printer_changed = 0;
		DD("send printer info %d bytes\n", send_count);
		DEBUG_OUT("search connected printers end...\n");
		DEBUG_OUT("\n");
		pthread_mutex_unlock(&g_search_mutex);
	}
	else
	{
		DD("print info reporter pause...\n");
	}
#endif

	DEBUG_OUT("Search connected printers...\n");
	pthread_mutex_lock(&g_search_mutex);
	g_report_state = 1;
	pthread_cond_signal(&g_search_cond);
	pthread_mutex_unlock(&g_search_mutex);
	DEBUG_OUT("search connected printers end...\n");
	DEBUG_OUT("\n");

	return;
}

void *report_printer_info_cb(void* arg)
{
	if(NULL == arg)
	{
		return NULL;
	}

	ack_param_t param;
	memset(&param, 0x0, sizeof(param));
	memcpy(&param, arg, sizeof(ack_param_t));
	DEBUG_OUT("Check Printer: server sock is %d, reporter stamp is %d\n", param.sock_fd, param.time_stamp);
	int stamp = param.time_stamp;
	if(stamp == 0)
	{
		stamp = REPORT_STAMP;
	}

	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = stamp;

	DEBUG_OUT("set reporter event\n");
	g_reporter_base = event_base_new();
	g_reporter_event = (struct event*)malloc(sizeof(struct event));
	event_set(g_reporter_event, param.sock_fd, EV_PERSIST, report_printer_proc, (void*)g_reporter_event);
	event_base_set(g_reporter_base, g_reporter_event);
	event_add(g_reporter_event, &tv);
	event_base_loop(g_reporter_base, 0);

	DD("reporter event exit...\n");
	return NULL;
}

void close_report_printer_proc()
{
	event_base_loopbreak(g_reporter_base);

	free(g_reporter_event);
	event_base_free(g_reporter_base);
	g_reporter_event = NULL;
	g_reporter_base = NULL;
}

void pause_report_printer_info()
{
	g_working_printers ++;
	DEBUG_OUT("printing count is %d\n", g_working_printers);
}

void resume_report_printer_info()
{
	g_working_printers --;
	DEBUG_OUT("printing count is %d\n", g_working_printers);
}

void *send_printer_info_cb(void* arg)
{
	long tmp = (long)arg;
	int fd = (int)tmp;

	while(!g_working_printers)
	{
		pthread_mutex_lock(&g_search_mutex);
		while(!g_report_state)
		{
			pthread_cond_wait(&g_search_cond, &g_search_mutex);
			usleep(1000);
		}
		g_report_state = 0;
		pthread_mutex_unlock(&g_search_mutex);

		pthread_mutex_lock(&g_print_mutex);
		DEBUG_OUT("send printers info...\n");
		search_connected_printers();
		int send_count = send_printer_info_to_server(fd);
		//g_report_state = 1;
		DD("send printer info %d bytes\n", send_count);
		DEBUG_OUT("send printer info %d bytes\n", send_count);
		DEBUG_OUT("send printers info end...\n");
		DEBUG_OUT("\n");
		pthread_mutex_unlock(&g_print_mutex);
	}

}

void init_printer_info_sender(int fd)
{
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, send_printer_info_cb, (void*)fd);
	pthread_detach(thread_id);
}

void init_report_printer_info(int fd, short stamp)
{
	pthread_t thread_id;
	ack_param_t *param = (ack_param_t*)malloc(sizeof(ack_param_t));
	memset(param, 0x0, sizeof(ack_param_t));
	param->sock_fd = fd;
	param->time_stamp = stamp;

	pthread_create(&thread_id, NULL, report_printer_info_cb, (void*)param);
	pthread_detach(thread_id);
	DD("repoter thread id is %d\n", (int)thread_id);

	init_printer_info_sender(fd);
}


//-------------------------------end-----------------------------------------//

//---------------------------usb hotplug check------------------------------//
int usb_hotplug_callback(struct libusb_context *ctx, struct libusb_device *dev,
							libusb_hotplug_event event, void *user_data)
{
	static libusb_device_handle *handle = NULL;
	struct libusb_device_descriptor desc;
	int rc;

	long server_fd = (long)user_data;
	int fd = (int)server_fd;

	//int ret = pthread_mutex_trylock(&g_search_mutex);
	//if(ret != 0)
	//{
	//	DEBUG_OUT("search printer locked when hotplug\n");
	//	return 0;
	//}
	DEBUG_OUT("usb device hotplug ..\n");
	(void)libusb_get_device_descriptor(dev, &desc);
	if(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED == event ||
			LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event )
	{
		//search_connected_printers();
		//send_printer_info_to_server(fd);
		pthread_mutex_lock(&g_search_mutex);
		g_report_state = 1;
		pthread_cond_signal(&g_search_cond);
		pthread_mutex_unlock(&g_search_mutex);
		DEBUG_OUT("usb device hotplug end..\n");
		DEBUG_OUT("\n");
	}
	//pthread_mutex_unlock(&g_search_mutex);

	return 0;
}

void *usb_hotplug_proc(void *arg)
{
	int rc;

	libusb_init(NULL);
	rc = libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG);
	if(rc == 0)
	{
		DEBUG_OUT("usb has no hotplug...\n");
		return NULL;
	}
	rc = libusb_hotplug_register_callback(NULL,
											LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
											LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
											0,
											LIBUSB_HOTPLUG_MATCH_ANY,
											LIBUSB_HOTPLUG_MATCH_ANY,
											LIBUSB_HOTPLUG_MATCH_ANY,
											usb_hotplug_callback,
											arg, &g_hotplug_handle);
	if(LIBUSB_SUCCESS != rc)
	{
		DEBUG_OUT("create usb hotplug callback error\n");
		libusb_exit(NULL);
		return NULL;
	}

	DEBUG_OUT("hotplug process begining...\n");
	exit_hotplug = 1;
	while(exit_hotplug)
	{
		libusb_handle_events_completed(NULL, NULL);
		usleep(10000);
	}

	DD("hotplug process exit...\n");
	return NULL;
}

void close_usb_hotplug_proc()
{
	if(g_hotplug_handle != 0)
	{
		libusb_hotplug_deregister_callback(NULL, g_hotplug_handle);
		libusb_exit(NULL);
	}

	exit_hotplug = 0;
}

void init_usb_hotplug_thread(int fd)
{
	pthread_t thread;
	pthread_create(&thread, NULL, usb_hotplug_proc, (void*)fd);
	pthread_detach(thread);
}


//-------------------------------end-------------------------------------- -//

//---------------------------heart beat functions-------------------------//
struct timeval lasttime;

static void pack_heart_beat_frame(heart_beat_t *frame)
{
	if(NULL == frame)
	{
		return;
	}

	heart_beat_t heart_beat_frame;
	memset(&heart_beat_frame, 0x0, sizeof(heart_beat_frame));

	heart_beat_frame.flag = SWAP16(CMD_SERVER_FLAG);
	heart_beat_frame.length = SWAP16(CMD_HEADER_LENGTH);
	heart_beat_frame.type = SWAP16(1);
	heart_beat_frame.version = SWAP16(1);
	heart_beat_frame.cmd = SWAP16(CMD_SERVER_ECHO);
	heart_beat_frame.enc_type = 0;
	heart_beat_frame.checksum = 0;

	unsigned char checksum = calc_bcc_checksum((void*)&heart_beat_frame, CMD_HEADER_LENGTH);
	heart_beat_frame.checksum = SWAP32(checksum);
	memcpy(frame, &heart_beat_frame, sizeof(heart_beat_frame));

	return;
}

void send_heart_beat(int fd, short event, void *arg)
{
	heart_beat_t heart_frame;
	memset(&heart_frame, 0x0, sizeof(heart_frame));
	pack_heart_beat_frame(&heart_frame);

	int write_count = write(fd, &heart_frame, sizeof(heart_frame));
	DD("Send heart-beat to server over:%d bytes\n", write_count);
	if(write_count < 0)
	{
		DEBUG_OUT("Disconnect...\n");
	}

	return;
}

void *heart_beat_proc(void* arg)
{
	if(NULL == arg)
	{
		return NULL;
	}

	DEBUG_OUT("HEART-BEAT:To running...\n");
	ack_param_t param;
	memset(&param, 0x0, sizeof(param));
	memcpy(&param, arg, sizeof(ack_param_t));
	free(arg);
	DEBUG_OUT("HEART-BEAT: server fd is %d, heart stamp is %d\n", param.sock_fd, param.time_stamp);
	int stamp = param.time_stamp;
	if(stamp == 0)
	{
		stamp = HEART_BEAT_STAMP;
	}

	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = stamp;

	DEBUG_OUT("set timer event\n");
	g_heartbeat_base = event_base_new();
	g_heartbeat_event = (struct event*)malloc(sizeof(struct event));
	event_set(g_heartbeat_event, param.sock_fd, EV_PERSIST, send_heart_beat, (void*)g_heartbeat_event);
	event_base_set(g_heartbeat_base, g_heartbeat_event);
	event_add(g_heartbeat_event, &tv);
	event_base_loop(g_heartbeat_base, 0);


	DEBUG_OUT("heart-beat event exit...\n");
	return NULL;
}

void close_heart_beat_proc()
{
	event_base_loopbreak(g_heartbeat_base);
#if 1
	free(g_heartbeat_base);
	event_base_free(g_heartbeat_base);

	g_heartbeat_base = NULL;
	g_heartbeat_event = NULL;
#endif
}

void init_heart_beat_thread(int fd, short stamp)
{
	pthread_t thread_id;
	ack_param_t* param = (ack_param_t*)malloc(sizeof(ack_param_t));
	if(param == NULL)
	{
		DEBUG_OUT("malloc fail\n");
		return;
	}
	memset(param, 0x0, sizeof(ack_param_t));
	param->sock_fd = fd;
	param->time_stamp = stamp;

	pthread_create(&thread_id, NULL, heart_beat_proc, (void*)param);
	pthread_detach(thread_id);
	DD("heatbeat thread id is %d\n", thread_id);
}
//--------------------------end-------------------------------------//

//-----------------------print functions----------------------------//
//epson uri like this: usb://EPOSON/LQ-630K?serial=0D5011507311435470
//hp uri like this:hp:/usb/HP_LaserJet_Professional_P1108?serial=xxxxxxxxx
//network printer like this: socket://x.x.x.x
char* pack_device_uri(int type, const char* brand, const char* model, const char* unique_flag)
{
	char* uri = NULL;
	char *usb_type = "usb";
	char *net_type = "socket";
	if(brand==NULL )
	{
		DEBUG_OUT("pack device uri failed, printer brand errer...\n");
		return NULL;
	}
	if(model==NULL)
	{
		DEBUG_OUT("pack device uri failed, printer model errer...\n");
		return NULL;
	}
	if(unique_flag==NULL)
	{
		DEBUG_OUT("pack device uri failed, printer sn errer...\n");
		return NULL;
	}

	uri = (char*)malloc(256);
	if(type == 0)
	{
		if(strcasecmp(brand, "hp") == 0)
		{
			sprintf(uri, "%s:/%s/%s_%s?serial=%s", brand, usb_type, brand, model, unique_flag);
		}
		else// (strcasecmp(brand, "epson") == 0)
		{
			sprintf(uri, "%s://%s/%s?serial=%s", usb_type, brand, model, unique_flag);
		}

	}
	else if(type == 1)
	{
		char *ip = get_ip_of_printer(unique_flag);
		sprintf(uri, "%s://%s", net_type, ip); //sn is ip address
	}
	DEBUG_OUT("device uri is %s\n", uri);

	return uri;
}

static int pack_print_result_frame(char* buf, char *file_id, char result)
{
	if(NULL == buf)
	{
		DEBUG_OUT("pack print result frame failed...\n");
		return -1;
	}
	int frame_len = 0;
	cmd_header_t header;
	print_result_t print_result;

	memset(&header, 0x0, sizeof(cmd_header_t));
	memset(&print_result, 0x0, sizeof(print_result_t));
	frame_len = CMD_HEADER_LENGTH + sizeof(print_result_t);
	DEBUG_OUT("frame len is %d\n", frame_len);
	//pack header
	header.flag = SWAP16(CMD_SERVER_FLAG);
	header.length = SWAP16(frame_len);
	header.type = SWAP16(1);
	header.version = SWAP16(1);
	header.cmd = SWAP16(CMD_SERVER_PRINT_RET);
	header.enc_type = 0;
	header.checksum = 0;

	strcpy(print_result.file_id, file_id);
	print_result.result = result;

	//pack frame : cmd_header + print_result
	memcpy(buf, &header, sizeof(header));
	memcpy(buf+sizeof(header), &print_result, sizeof(print_result));

	//overwrite cmd_header
	int checksum = calc_bcc_checksum((void*)buf, frame_len);
	header.checksum = SWAP32(checksum);

	memcpy(buf, (void*)&header, sizeof(header));

	return frame_len;
}

int send_print_result_to_server(int fd, char* file_id, char result)
{
	if(fd < 0)
	{
		DEBUG_OUT("send print result failed, socket error\n");
		return -1;
	}

	if(NULL == file_id)
	{
		DEBUG_OUT("send print result failed,file id error\n");
		return -1;
	}
	char *result_frame = NULL;
	int buf_len = 0;
	int send_count = 0;

	buf_len = sizeof(cmd_header_t) + sizeof(print_result_t);
	result_frame = (char*)malloc(buf_len);
	if(NULL == result_frame)
	{
		DEBUG_OUT("malloc memory failed when send print result...\n");
		return -1;
	}
	memset(result_frame, 0x0, buf_len);

	pack_print_result_frame(result_frame, file_id, result);

	send_count = send(fd, result_frame, buf_len, 0);
	if(send_count <= 0)
	{
		DEBUG_OUT("send print result failed, %s\n", strerror(errno));
		free(result_frame);
		return -1;
	}

	DEBUG_OUT("send print result over:%d bytes send...\n", send_count);
	free(result_frame);

	return 0;
}

void *print_cb(void *arg)
{
	if(NULL == arg)
	{
		DEBUG_OUT("print failed, param error...\n");
		return NULL;
	}

	print_ret_param param;
	memset(&param, 0x0, sizeof(print_ret_param));
	memcpy(&param, arg, sizeof(print_ret_param));
	free(arg);

	int fd = param.fd;
	print_req_t print_req;
	memset(&print_req, 0x0, sizeof(print_req_t));
	memcpy(&print_req, &param.print_req, sizeof(print_req_t));

	pthread_mutex_lock(&g_print_mutex);
	//get printer
	int type = get_type_of_printer(print_req.printer_unique_flag);
	char* brand = get_brand_of_printer(print_req.printer_unique_flag);
	char* model = get_model_of_printer(print_req.printer_unique_flag);

	DEBUG_OUT("PRINTER:%s %s, type is %d\n", brand, model, type);
	if(brand==NULL||model==NULL)
	{
		DEBUG_OUT("printer %s not exist\n", print_req.printer_unique_flag);
		//send print ruselt to server
		send_print_result_to_server(fd, print_req.file_id, 0);
		return NULL;
	}

	//pack device_uri for usb printer
	char *device_uri = pack_device_uri(type, brand, model, print_req.printer_unique_flag);
	if(device_uri == NULL)
	{
		DEBUG_OUT("device_uri pack failed of printer %s\n", print_req.printer_unique_flag);
		send_print_result_to_server(fd, print_req.file_id, 0);
		return NULL;
	}

	char print_doc[256] = {0};
	strcpy(print_doc, PRINT_DOC);
	char *file = strcat(print_doc, print_req.file_id);
	DD("print file is %s\n", file);
	//cmd to print
	pause_report_printer_info();

	int ret = -1;
	if(type == 0) //usb printer
	{
		if(strcasecmp(brand, "hp") == 0)
		{
			ret = print_hp_file(device_uri, file);
		}
		else
		{
			ret = print_file(device_uri, file);
		}
	}
	else if(type == 1) //network printer
	{
		ret= send_file(device_uri, file);
	}


	if(ret == 0)
	{
		send_print_result_to_server(fd, print_req.file_id, 1);
	}

	free(device_uri);
	unlink(file);
	DD("%s print OK\n", file);
	pthread_mutex_unlock(&g_print_mutex);
	resume_report_printer_info();

	return NULL;
}

void init_print_thread(int fd, void *arg)
{
	pthread_t thread_id;
	print_ret_param *param = (print_ret_param *)malloc(sizeof(print_ret_param));
	memcpy(param, arg, sizeof(print_req_t));
	param->fd = fd;
	DEBUG_OUT("print param flag is %s\n", param->print_req.printer_unique_flag);
	DEBUG_OUT("print param file is %s\n", param->print_req.file_id);
	free(arg);

	pthread_create(&thread_id, NULL, print_cb, (void*)param);
	pthread_detach(thread_id);

	return;
}
//------------------------------------------------------------------//

//------------------------communicate with server ----------------------//
static int md5_signature(char* md5_buf)
{
	//cacl signature
	char in_buf[128] = {0};
	char out_buf[128] = {0};

	if(md5_buf == NULL)
	{
		return -1;
	}

	time_t stamp;
	time(&stamp);

	char sn[32] = {0};
#ifdef BOX
	get_sn_of_device(sn);
#else
	strcpy(sn, "123456789abcde");
#endif
	strcpy(in_buf, COMM_KEY);
	strcat(in_buf, sn);
	DEBUG_OUT("MD5 PARAMS:%s\n", in_buf);
	cacl_md5(in_buf, out_buf);	//md5(key+sn)
	memset(in_buf, 0x0, sizeof(in_buf));

	DEBUG_OUT("MD5:%s\n", out_buf);
	strcpy(in_buf, out_buf);
	memset(out_buf, 0x0, sizeof(out_buf));
	char time_stamp[16] = {0};
	sprintf(time_stamp, "%d", stamp);
	strcat(in_buf, time_stamp);
	DEBUG_OUT("MD5 PARAMS:%s\n", in_buf);
	cacl_md5(in_buf, out_buf);
	memset(in_buf, 0x0, sizeof(in_buf));
	DEBUG_OUT("SIGNATURE:%s\n", out_buf);
	if(strlen(out_buf) != 32)
	{
		DEBUG_OUT("md5 signature failed\n");
		return -1;
	}

	strcpy(md5_buf, out_buf);

	return 0;
}

static int pack_request_ack_frame(void *buf)
{
	int frame_len = 0;
	cmd_header_t header;
	req_frame_t req_frame;

	if(NULL == buf)
	{
		DEBUG_OUT("connect frame error\n");
		return -1;
	}

	memset(&header, 0x0, sizeof(header));
	memset(&req_frame, 0x0, sizeof(req_frame));
	frame_len = CMD_HEADER_LENGTH + sizeof(req_frame_t);
	DEBUG_OUT("frame len is %d\n", frame_len);
	//pack header
	header.flag = SWAP16(CMD_SERVER_FLAG);
	header.length = SWAP16(frame_len);
	header.type = SWAP16(1);
	header.version = SWAP16(1);
	header.cmd = SWAP16(CMD_SERVER_REQ);
	header.enc_type = 0;
	header.checksum = 0;

	//pack frame

#ifdef BOX
	get_sn_of_device(req_frame.box_sn);
#else
	strcpy(req_frame.box_sn, "123456789abcde");
#endif
	strcpy(req_frame.version, VERSION);

	time_t stamp;
	time(&stamp);
	req_frame.timestamp = SWAP32(stamp);

	char md5[32] = {0};
	md5_signature(md5);
	strcpy(req_frame.signature, md5);

	get_version_of_system(req_frame.sys_ver);

	//pack frame : cmd_header + req_farme
	memcpy(buf, &header, sizeof(header));
	memcpy(buf+sizeof(header), &req_frame, sizeof(req_frame));

	//overwrite cmd_header
	int checksum = calc_bcc_checksum((void*)buf, frame_len);
	header.checksum = SWAP32(checksum);

	memcpy(buf, (void*)&header, sizeof(header));

	return frame_len;
}

static int pack_ack_frame(char *buf, int cmd)
{
	if(NULL == buf)
	{
		return -1;
	}

	cmd_header_t header;
	memset(&header, 0x0, sizeof(header));

	header.flag = SWAP16(CMD_SERVER_FLAG);
	header.length = SWAP16(CMD_HEADER_LENGTH);
	header.type = SWAP16(1);
	header.version = SWAP16(1);
	header.cmd = SWAP16(cmd);
	header.enc_type = 0;

	char checksum = calc_bcc_checksum(&header, CMD_HEADER_LENGTH);
	header.checksum = SWAP32(checksum);

	memcpy(buf, &header, sizeof(header));

	return CMD_HEADER_LENGTH;
}



int send_req_frame_to_server(int fd)
{
	char *req_frame = NULL;
	int buf_len = 0;
	int send_count = 0;

	if(fd < 0)
	{
		DEBUG_OUT("send req frame fail, socket error\n");
		return -1;
	}

	buf_len = sizeof(cmd_header_t) + sizeof(req_frame_t);
	req_frame = (char*)malloc(buf_len);
	if(NULL == req_frame)
	{
		DEBUG_OUT("malloc memory failed when send req frame\n");
		return -1;
	}
	pack_request_ack_frame(req_frame);

	send_count = send(fd, req_frame, buf_len, 0);
	if(send_count <= 0)
	{
		DEBUG_OUT("send req frame failed, %s\n", strerror(errno));
		free(req_frame);
		return -1;
	}

	DEBUG_OUT("send req frame over:%d bytes send...\n", send_count);
	free(req_frame);

	return send_count;
}

int send_config_ack_to_server(int fd)
{
	cmd_header_t ack;
	memset(&ack, 0x0, sizeof(cmd_header_t));

	if(fd < 0)
	{
		DEBUG_OUT("send config ack error...\n");
	}
	pack_ack_frame((char*)&ack, CMD_SERVER_CFG_ACK);

	int send_count = send(fd, &ack, sizeof(cmd_header_t), 0);
	if(send_count == sizeof(cmd_header_t))
	{
		DEBUG_OUT("send config ack OK\n");
		return 0;
	}

	return -1;
}

int send_update_ack_to_server(int fd)
{
	cmd_header_t ack;
	memset(&ack, 0x0, sizeof(cmd_header_t));

	if(fd < 0)
	{
		DEBUG_OUT("send update ack error...\n");
	}
	pack_ack_frame((char*)&ack, CMD_SERVER_UPDATE_ACK);

	int send_count = send(fd, &ack, sizeof(cmd_header_t), 0);
	if(send_count == sizeof(cmd_header_t))
	{
		DEBUG_OUT("send update ack OK\n");
		return 0;
	}

	return -1;
}

int send_print_ack_to_server(int fd)
{
	cmd_header_t ack;
	memset(&ack, 0x0, sizeof(cmd_header_t));

	if(fd < 0)
	{
		DEBUG_OUT("send print ack error...\n");
		return -1;
	}
	pack_ack_frame((char*)&ack, CMD_SERVER_PRINT_ACK);

	int send_count = send(fd, &ack, sizeof(cmd_header_t), 0);
	if(send_count == sizeof(cmd_header_t))
	{
		DEBUG_OUT("send print ack OK\n");
		return 0;
	}

	return -1;
}

int send_disconnect_req_to_server(int fd)
{
	cmd_header_t ack;
	memset(&ack, 0x0, sizeof(cmd_header_t));

	if(fd < 0)
	{
		DEBUG_OUT("send disconnect req error...\n");
		return -1;
	}
	pack_ack_frame((char*)&ack, CMD_SERVER_DISCONNECT);

	int send_count = send(fd, &ack, sizeof(cmd_header_t), 0);
	if(send_count == sizeof(cmd_header_t))
	{
		DEBUG_OUT("send disconnect req OK\n");
		return 0;
	}

	return -1;
}


int read_ack_data_from_server(int fd)
{
	unsigned char ack = 0x0;
	int ack_len = 1;
	int read_count = 0;

	//read_count = read(fd, &ack, ack_len);
	char* ptr = get_buffer(ack_len);
	ack = (unsigned char)*ptr;
	if(ack==0)
	{
		DEBUG_OUT("read ack frame length is %d\n", read_count);
		DEBUG_OUT("read ack frame error: %s\n", strerror(errno));
		send_req_frame_to_server(fd);
		return -1;
	}
	release_buffer(ack_len);
	DEBUG_OUT("recv Ack Ok~~~~~~~~~~~~\r\n");

	return 0;
}

int read_update_data_from_server(int fd, short length)
{
	if(fd < 0 || length <= 0)
	{
		DEBUG_OUT("read update data error\n");
		return -1;
	}
	DEBUG_OUT("length of udpate data is %d\n", length);

	int ret = -1;
	//int read_count = 0;
	int req_length = sizeof(update_req_t);
	update_req_t update_req;
	memset(&update_req, 0x0, req_length);

	char *ptr = get_buffer(req_length);
	if(ptr == NULL)
	{
		DEBUG_OUT("no update req....\n");
		return -1;
	}
	memcpy(&update_req, ptr, req_length);
	release_buffer(req_length);
	ptr = NULL;

	int addr_len = SWAP16(update_req.addr_len);
	if(addr_len <= 0)
	{
		DEBUG_OUT("download addr len error\n");
		return -1;
	}
	DEBUG_OUT("length of addr is %d\n", addr_len);

	char *load_addr = (char *)malloc(addr_len+1);
	memset(load_addr, 0x0, addr_len);
	ptr = get_buffer(addr_len);
	if(NULL == ptr)
	{
		DEBUG_OUT("no update addr query...\n");
		return -1;
	}
	memcpy(load_addr, ptr, addr_len);
	release_buffer(addr_len);
	ptr = NULL;
	DEBUG_OUT("version is %s\n", update_req.version);
	DEBUG_OUT("addr is %s\n", load_addr);
	DEBUG_OUT("recv update req OK\n");
	DEBUG_OUT("send update ack\n");
	send_update_ack_to_server(fd);

	if(strcmp(update_req.version, VERSION) > 0)
	{
		ret = start_download(load_addr, DOWNLOAD_FILE);
		if(ret == 0)
		{
			DEBUG_OUT("download update file OK!!!\n");
			//send disconnect ack to server
			send_disconnect_req_to_server(fd);
			//exit(0);
		}
	}

	return -1;
}

int read_config_data_from_server(int fd)
{
	//int read_count = 0;
	box_cfg_t cfg;
	int ack_len = sizeof(box_cfg_t);
	memset(&cfg, 0x0, ack_len);

	//read_count = read(fd, &cfg, ack_len);
	char *ptr = get_buffer(ack_len);
	if(NULL == ptr)
	{
		DEBUG_OUT("read config req error\n");
		return -1;
	}
	DEBUG_OUT("recv config data OK\n");
	send_config_ack_to_server(fd);

	memcpy(&cfg, ptr, ack_len);
	release_buffer(ack_len);
	ptr = NULL;

	g_report_stamp = SWAP16(cfg.echo_stamp);
	init_heart_beat_thread(fd, g_report_stamp);
	g_report_stamp = SWAP16(cfg.check_stamp);
	init_report_printer_info(fd, g_report_stamp);

	return 0;
}


int read_print_data_from_server(int fd)
{
	if(fd < 0)
	{
		DEBUG_OUT("read print data fail, sock fd error\n");
		return -1;
	}

	int req_len = sizeof(print_req_t);
	print_req_t *print_req = (print_req_t *)malloc(req_len);
	memset(print_req, 0x0, req_len);

	//read_count = read(fd, &print_req, req_len);
	char *ptr = get_buffer(req_len);
	if(NULL == ptr)
	{
		DEBUG_OUT("read print param error\n");
		return -1;
	}
	memcpy(print_req, ptr, req_len);
	release_buffer(req_len);
	ptr = NULL;

#ifdef DEBUG
	DEBUG_OUT("***********************************************\n");
	int i = 0;
	char tmp_buf[68] = {0};
	memcpy(tmp_buf, print_req, req_len);
	for(i=0; i<req_len; i++)
	{
		printf("0x%02x ", (unsigned char)tmp_buf[i]);
		if(i%8==7)
		{
			printf("\n");
		}
	}
	printf("\n");
	DEBUG_OUT("**********************************************\n");
#endif

	int file_len = SWAP32(print_req->file_length);
	DEBUG_OUT("length of file to print is %d\n", file_len);

	char print_doc[256] = {0};
	strcpy(print_doc, PRINT_DOC);
	char *print_file = strcat(print_doc, print_req->file_id);
	int print_file_fd = open(print_file, O_RDWR | O_CREAT | O_TRUNC);
	if(print_file_fd < 0)
	{
		DD("%s open or create failed\n", print_file);
		return -1;
	}
	int write_count = 0;
	int read_count = 64*1024;
	while(write_count != file_len)
	{
		if(file_len - write_count < read_count)
		{
			read_count = file_len - write_count;
		}

		ptr = get_buffer(read_count);
		if(NULL == ptr)
		{
			DEBUG_OUT("no data of print file read...\r\n");
			sleep(1);
			continue;
		}
		write(print_file_fd, ptr, read_count);
		release_buffer(read_count);
		ptr = NULL;
		write_count += read_count;

	}
	DEBUG_OUT("recv print file over,length is %d\n", write_count);
	close(print_file_fd);

	send_print_ack_to_server(fd);

	//To print data
	init_print_thread(fd, (void *)print_req);

	return 0;
}

void close_parse_proc()
{
	exit_parse = 0;
}

int parse_ack_frame_from_server(int fd)
{
	int read_count = 0;

	if(fd < 0)
	{
		DEBUG_OUT("parse ack frame failed, socket error\n");
		return -1;
	}

	cmd_header_t header;
	int len = sizeof(cmd_header_t);
	memset(&header, 0x0, len);

	DEBUG_OUT("parse process begin...\n");
	exit_parse = 1;
	while (exit_parse)
	{
		char *frame = get_buffer(len);
		if(NULL == frame)
		{
			sleep(1);
			continue;
		}
		memcpy(&header, frame, len);
		release_buffer(len);

		DEBUG_OUT("frame header flag is 0x%4x\n", header.flag);
		if(SWAP16(header.flag) != CMD_SERVER_FLAG &&
				SWAP16(header.type) != 1 &&
				SWAP16(header.version) != 1)
		{
			DEBUG_OUT("parse ack frame header error...\n");
			continue;
		}

	#if 0
		if(check_frame((void*)&header, CMD_HEADER_LENGTH) != 0)
		{
			DEBUG_OUT("parse ack frame but checksum error...\n");
			return -1;
		}
	#endif

		short cmd = SWAP16(header.cmd);
		DEBUG_OUT("server cmd is %d\n", cmd);

		if(cmd == CMD_SERVER_ACK)
		{
			DEBUG_OUT("***********************************************\n");
			DEBUG_OUT("recv ack frame\n");
			read_ack_data_from_server(fd);
			DEBUG_OUT("***********************************************\n");
		}
		else if(cmd == CMD_SERVER_PRINT_REQ)
		{
			DEBUG_OUT("***********************************************\n");
			DEBUG_OUT("recv print req\n");
			read_print_data_from_server(fd);
			DEBUG_OUT("***********************************************\n");
		}
		else if(cmd == CMD_SERVER_UPDATE_REQ)
		{
			DEBUG_OUT("***********************************************\n");
			DEBUG_OUT("recv update req\n");
			read_update_data_from_server(fd, SWAP16(header.length)-CMD_HEADER_LENGTH);
			DEBUG_OUT("***********************************************\n");
		}
		else if(cmd == CMD_SERVER_CFG_REQ)
		{
			DEBUG_OUT("***********************************************\n");
			DEBUG_OUT("recv config req...\n");
			read_config_data_from_server(fd);
			DEBUG_OUT("***********************************************\n");
		}
		else
		{
			DEBUG_OUT("recv error req frame\n");
		}
	}

	DD("parse process exit...\n");

	return 0;
}
//---------------------------end---------------------------------//
