/*
 * client.c
 *
 *  Created on: Oct 21, 2016
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
#include <arpa/inet.h>
#include <time.h>

#include <event.h>
#include <event2/util.h>

#include "util.h"
#include "databuffer.h"
#include "app_comm.h"
#include "server_comm.h"

#define BUF_SIZE	(32*1024*1024)

char g_server_addr[256] = {0};
int g_server_port = 0;

static struct event_base *g_main_base = NULL;
static struct event *g_main_event = NULL;


/***************************************************/
void* init_ack_app_cb(void *arg)
{
	send_sn_to_app();

	return NULL;
}

void init_ack_app_thread()
{
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, init_ack_app_cb, NULL);
	pthread_detach(thread_id);
}
/**************************************************/

/**************************************************/
void* init_parse_frame_cb(void *arg)
{
	long tmp = (long)arg;
	int fd = (int)tmp;

	parse_ack_frame_from_server(fd);

	return NULL;
}



void init_parse_thread(int fd)
{
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, init_parse_frame_cb, (void*)fd);
	pthread_detach(thread_id);
}
/**************************************************/
void disconnect()
{
	close_usb_hotplug_proc();
	close_parse_proc();

	close_heart_beat_proc();
	close_report_printer_proc();
}


void on_read(int fd, short event, void *arg)
{
	static int read_size = 1024;
	char *ptr = get_free_buffer(read_size);
	if(NULL == ptr)
	{
		DD("no space to store data...\n");
		return;
	}

	int read_count = read(fd, ptr, read_size);
	if(read_count <= 0)
	{
		DD("No data read from socket, %s\n", strerror(errno));
		disconnect();

		sleep(1);
		event_base_loopbreak(g_main_base);
		free(g_main_event);
		event_base_free(g_main_base);

		return;
	}
	use_free_buffer(read_count);


#ifdef DEBUG
	int i = 0;
	char tmp_buf[CMD_HEADER_LENGTH] = {0};
	memcpy(tmp_buf, ptr, CMD_HEADER_LENGTH);
	for(i=0; i<CMD_HEADER_LENGTH; i++)
	{
		printf("0x%02x ", (unsigned char)tmp_buf[i]);
		if(i%8==7)
		{
			printf("\n");
		}
	}
	printf("\n");
#endif

	return;
}


int connect_server(char* server, int port)
{
	if(NULL == server)
	{
		DD("server addr error...\n");
		return -1;
	}


	char *ip = (char *)malloc(16);
	if(NULL == ip)
	{
		DD("malloc server ip error...\n");
		return -1;
	}

	DD("server address is %s\n",server);
	if(check_ip_address(server) == 1)
	{
		strcpy(ip, server);
	}
	else
	{
		DD("server is %s\n", server);
		if(get_ip_by_domain(server, ip) != 0)
		{
			DD("get server ip %s error...\n", ip);
			free(ip);
			return -1;
		}
	}


	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
	{
		DD("socket create error\n");
		free(ip);
		return -1;
	}

	struct sockaddr_in server_addr;
	memset(&server_addr, 0x0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_port = htons(port);
	free(ip);

	int status = connect(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
	if(status < 0)
	{
		DD("Connect to server error,%s\n", strerror(errno));
		return -1;
	}

	evutil_make_socket_nonblocking(fd);
	if(fd > 0)
	{
		send_req_frame_to_server(fd);
	}

	//search_connected_printers();
	//send_printer_info_to_server(fd);

	//
	init_parse_thread(fd);
	init_usb_hotplug_thread(fd);

	DD("Cloud print server running~~~~~\n");
	g_main_base = event_base_new();
	g_main_event = (struct event*)malloc(sizeof(struct event));

	event_set(g_main_event, fd, EV_READ|EV_PERSIST, on_read, NULL);
	event_base_set(g_main_base, g_main_event);
	event_add(g_main_event, NULL);
	event_base_loop(g_main_base, 0);

	DD("Cloud print server exit....\n");



	return fd;
}

int main(int argc, char** argv)
{
	if(argc == 2)
	{
		if(strcmp(argv[1], "-v") == 0)
		{
			printf(VERSION);
		}

		return 0;
	}
	else if(argc != 3)
	{
		DD("Please input correct params\n");
		DD("Usage:print-server server_addr server_port\n");
		return -1;
	}

	strcpy(g_server_addr, argv[1]);
	g_server_port = atoi(argv[2]);

	//recv broadcast from app
	init_buffer(BUF_SIZE);
	init_ack_app_thread();

	//connect_server(g_server_addr, g_server_port);

	while (1)
	{
		connect_server(g_server_addr, g_server_port);

		DD("To wait...\n");
		sleep(5);
	}


#if 0
	//---------------------
	char buffer[1024] = {0};
	int break_flag = 0;
	while(!break_flag)
	{
		printf("Input your data to server(\'q\' or \'quit\' to exit)...\n");
		gets(buffer);
		if(strcmp("q", buffer) == 0
		|| strcmp("quit", buffer) == 0)
		{
			break_flag = 1;
			close(fd);
			break;
		}

		printf("Your input is:%s\n", buffer);
		int write_count = write(fd, buffer, strlen(buffer));
		printf("%d characters written.\n", write_count);

		sleep(2);
	}
#endif

	destroy_buffer();
	printf("Program exit...\n");

	return 0;

}



