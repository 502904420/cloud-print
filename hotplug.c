/*
 * hotplug.c
 *
 *  Created on: Oct 22, 2016
 *      Author: root
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include <libusb-1.0/libusb.h>

#define UEVENT_BUFFER_SIZE 2048

static int init_hotplug_sock()
{
	const int buffer_size = 1024;
	int ret;
	struct sockaddr_nl snl;
	bzero(&snl, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 1;

	int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if(-1 == fd)
	{
		printf("create socket error!\n");
		return -1;
	}

	ret = bind(fd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl));
	if(ret < 0)
	{
		printf("socket bind error\n");
		close(fd);
		return -1;
	}

	return fd;
}

void *hotplug_cb(void* arg)
{
	int hotplug_sock = init_hotplug_sock();

	while(1)
	{
		char buf[UEVENT_BUFFER_SIZE*2] = {0};
		recv(hotplug_sock, &buf, sizeof(buf), 0);
		printf("%s\n", buf);
	}
}

void init_hotplug_thread()
{
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, hotplug_cb, NULL);
	pthread_detach(thread_id);
}


static int count = 0;
int hotplug_callback(struct libusb_context *ctx, struct libusb_device *dev,
						libusb_hotplug_event event, void *user_data)
{
	static libusb_device_handle *handle = NULL;
	struct libusb_device_descriptor desc;
	int rc;

	(void)libusb_get_device_descriptor(dev, &desc);
	if(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED == event)
	{
		rc = libusb_open(dev,&handle);
		if(LIBUSB_SUCCESS != rc)
		{
			printf("Could not open USB device\n");
		}
		printf("usb device arrived..\n");
	}
	else if(LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event)
	{
		if(handle)
		{
			libusb_close(handle);
			handle = NULL;
		}
		printf("usb device left...\n");
	}
	else
	{
		printf("Unhandle event %d\n", event);
	}
	count ++;

	return 0;
}

int main(int agrc, char **argv)
{
#if 0
	init_hotplug_thread();

	while(1)
	{
		sleep(5);

	}
#endif
	
	libusb_hotplug_callback_handle handle;
	int rc;
	
	libusb_init(NULL);
#if 0
	rc = libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG);
	if(rc == 0)
	{
		printf("LIBUSB has no capability to hotplug\n");
		return -1;
	}
#endif
	rc = libusb_hotplug_register_callback(NULL, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | 
											LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, 0, 
											LIBUSB_HOTPLUG_MATCH_ANY,LIBUSB_HOTPLUG_MATCH_ANY,
											LIBUSB_HOTPLUG_MATCH_ANY, hotplug_callback, NULL,
											&handle);
	if(LIBUSB_SUCCESS != rc)
	{
		printf("Error creating hotplug callback\n");
		libusb_exit(NULL);

		return -1;
	}

	while(1)
	{
		libusb_handle_events_completed(NULL, NULL);
		usleep(10000);
	}

	libusb_hotplug_deregister_callback(NULL, handle);
	libusb_exit(NULL);

	return 0;
}
