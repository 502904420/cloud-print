/*
 * client.c
 *
 *  Created on: Nov 25, 2016
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <event.h>
#include <event2/util.h>

#include "util.h"

bufferevent_data_cb  bufferread_cb()
{

}

bufferevent_data_cb bufferwrite_cb()
{

}

bufferevent_data_cb bufferevent_cb()
{

}

int main(int argc, char *argv[])
{
	if(argc != 3)
	{
		printf("Please input correct params\n");
		printf("Usage:client server_ip server_port\n");
		return -1;
	}

	char *ip = (char *)malloc(16);
	if(NULL == ip)
	{
		printf("malloc server ip error...\n");
		return -1;
	}
	if(check_ip_address(argv[1]) == 1)
	{
		strcpy(ip, argv[1]);
	}
	else
	{
		if(get_ip_by_domain(argv[1], ip) != 0)
		{
			printf("get server ip %s error...\n", ip);
			free(ip);
			return -1;
		}
	}

	struct event_base *base;
	struct bufferevent *bev;
	struct sockaddr_in sin;
	memset(&sin, 0x0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(argv[2]);
	inet_aton(ip, &sin.sin_addr.s_addr);

	base = event_base_new();
	bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, bufferread_cb, bufferwrite_cb, bufferevent_cb, base);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin));





	return 0;
}
