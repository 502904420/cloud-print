/*
 * main.c
 *
 *  Created on: Oct 17, 2016
 *      Author: root
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <time.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event.h>

#include "server_comm.h"
#include "util.h"

#define SERVER_PORT	54321

#ifdef __ANDROID__
#include <android/log.h>
#define DD(...) __android_log_print(ANDROID_LOG_DEBUG, "print-server", __VA_ARGS__)
#else
#define DD(...) fprintf(stderr, __VA_ARGS__)
#endif

#define DEBUG

typedef struct read_sock_ev
{
	struct event_base *base;
	struct event *read_ev;
};

typedef struct write_sock_ev
{
	struct event *write_ev;
	char *buffer;
};

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

int write_req_ack_frame_to_client(int fd, char ack)
{
	cmd_header_t frame;
	memset(&frame, 0x0, sizeof(cmd_header_t));

	if(fd < 0)
	{
		DEBUG_OUT("send req ack error...\n");
		return -1;
	}
	pack_ack_frame((char*)&frame, CMD_SERVER_ACK);

	int send_count = send(fd, &frame, sizeof(cmd_header_t), 0);
	send_count += send(fd, &ack, sizeof(char), 0);
	if(send_count == sizeof(char)+sizeof(cmd_header_t))
	{
		DEBUG_OUT("send req ack OK!\n");
		return 0;
	}

	return -1;
}

int write_config_data_to_client(int fd)
{
	box_cfg_t cfg;
	memset(&cfg, 0x0, sizeof(cfg));
	cfg.check_stamp = SWAP16(5);
	cfg.echo_stamp = SWAP16(10);

	cmd_header_t header;
	memset(&header, 0x0, sizeof(header));

	pack_ack_frame(&header, CMD_SERVER_CFG_REQ);
	int send_count = send(fd, &header, sizeof(cmd_header_t), 0);
	send_count += send(fd, &cfg, sizeof(box_cfg_t), 0);
	if(send_count == sizeof(box_cfg_t)+sizeof(cmd_header_t))
	{
		DEBUG_OUT("send config req OK!\n");
		return 0;
	}

	return 0;
}

void destroy_write_sock_ev(struct write_sock_ev *arg)
{
	if(NULL == arg)
	{
		return;
	}

	if(NULL != arg->write_ev)
	{
		free(arg->write_ev);
	}

	if(NULL != arg->buffer)
	{
		free(arg->buffer);
	}

	free(arg);

	return;
}

void destroy_read_sock_ev(struct read_sock_ev *arg)
{
	if(NULL == arg)
	{
		return;
	}

	event_del(arg->read_ev);
	event_base_loopexit(arg->base, NULL);

	if(NULL != arg->read_ev)
	{
		free(arg->read_ev);
	}

	event_base_free(arg->base);
	free(arg);

	return;
}

static void on_write(int fd, short event, void *arg)
{
	if(NULL == arg)
	{
		DD("%s-%d-%s:param error...\n", __FILE__, __LINE__, __func__);
		return;
	}

	struct write_sock_ev *write_sock = (struct write_sock_ev *)arg;

	char buffer[1024] = {0};
	sprintf(buffer, "fd=%d, received[%s]", fd, write_sock->buffer);


	int write_num = write(fd, buffer, strlen(buffer));
	DD("Write %d characters to client...\n", write_num);

	destroy_write_sock_ev(write_sock);

	return;
}

static void on_read(int fd, short event, void *arg)
{
	if(NULL == arg)
	{
		DD("%s-%d-%s:param error...\n", __FILE__, __LINE__, __func__);
		return;
	}

	struct read_sock_ev *event_struct = (struct read_sock_ev *)arg;
	char* buffer = malloc(1024);
	memset(buffer, 0x0, 1024);

	int size = read(fd, buffer, 20);
	if(0 == size)
	{
		DD("%s-%d-%s:no client connected...\n", __FILE__, __LINE__, __func__);
		free(buffer);
		close(fd);
		return;
	}
	DD("Server received %d bytes\n", size);
#ifdef DEBUG
	int i = 0;	
	for(i=0; i<size; i++)
	{
		printf("0x%02x ", (unsigned char)buffer[i]);
		if(i%8==7)
		{
			printf("\n");	
		}
	}
#endif

	struct write_sock_ev *write_struct = (struct write_sock_ev *)malloc(sizeof(struct write_sock_ev));
	write_struct->buffer = buffer;

	struct event *write_ev = (struct event*)malloc(sizeof(struct event));
	write_struct->write_ev = write_ev;

	event_set(write_ev, fd, EV_WRITE, on_write, write_struct);
	event_base_set(event_struct->base, write_ev);
	event_add(write_ev, NULL);

	return;
}



static void* process_client(void *arg)
{
	int fd = (int)*((int*)arg);
	if(fd < 0)
	{
		DD("%s-%d-%s:socket fd error...\n", __FILE__, __LINE__, __func__);
		return NULL;
	}

	write_req_ack_frame_to_client(fd, 1);
	write_config_data_to_client(fd);

	//--------------initalize base---------------
	struct event_base *base = event_base_new();
	struct event *read_ev = (struct event *)malloc(sizeof(struct event));

	//----------base,read_ev, write_ev-----
	struct read_sock_ev* event_struct = (struct read_sock_ev*)malloc(sizeof(struct read_sock_ev));
	event_struct->base = base;
	event_struct->read_ev = read_ev;

	//---------------------------
	event_set(read_ev, fd, EV_READ|EV_PERSIST, on_read, event_struct);
	event_base_set(base, read_ev);
	event_add(read_ev, NULL);

	event_base_dispatch(base);
	destroy_read_sock_ev(event_struct);
	DD("client thread exit...\n");

	return 0;
}

static void accept_new_thread(int fd)
{
	pthread_t thread_id;

	pthread_create(&thread_id, NULL, process_client, (void *)&fd);

	pthread_detach(thread_id);
}

/*
 * when new client connected to server, libevent call this func
  * every connection directs to a new thread
 */
static void accept_client(int fd, short event, void *arg)
{
	struct sockaddr_in remote_addr;
	int size = sizeof(struct sockaddr_in);
	memset(&remote_addr, 0x0, size);

	DD("Waiting for client...\n");
	int new_fd = accept(fd, (struct sockaddr*)&remote_addr, (socklen_t*)&size);
	if(new_fd < 0)
	{
		DD("%s-%d-%s:accept error...\n", __FILE__, __LINE__, __func__);
		return;
	}

	accept_new_thread(new_fd);

	return;
}

int main(int argc, char** argv)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == fd)
	{
		DD("%s-%d-%s:Create socket fd error...\n", __FILE__, __LINE__, __func__);
		return -1;
	}

	DD("Running server~~~~\n");
	
	struct sockaddr_in local_addr;
	memset(&local_addr, 0x0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(SERVER_PORT);

	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	int bind_result = bind(fd, (struct sockaddr*)&local_addr, sizeof(struct sockaddr));
	if(bind_result < 0)
	{
		DD("%s-%d-%s:bind socket error...\n", __FILE__, __LINE__, __func__);
	}

	int listen_result = listen(fd, 10);
	if(listen_result < 0)
	{
		DD("%s-%d-%s:listen socket error...\n", __FILE__, __LINE__, __func__);
	}

	//---------------set libevent----------------
	struct event_base *base = event_base_new();
	struct event listen_ev;
	event_set(&listen_ev, fd, EV_READ|EV_PERSIST, accept_client, NULL);
	event_base_set(base, &listen_ev);
	event_add(&listen_ev, NULL);
	event_base_dispatch(base);


	//---------------destroy-------------------
	event_del(&listen_ev);
	event_base_free(base);

	return 0;
}



