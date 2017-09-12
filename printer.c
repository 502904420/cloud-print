/*
 * printer.c
 *
 *  Created on: Feb 18, 2017
 *      Author: root
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "printer.h"
#include "util.h"

static printer_list_t *g_printer_list = NULL;
static int g_printer_count = 0;
static pthread_mutex_t g_printer_mutex = PTHREAD_MUTEX_INITIALIZER;


int check_printer_exist(const char* unique_flag)
{
	printer_list_t **tmp;
	int ret = 0;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		DEBUG_OUT("no printer exist...\n");
		pthread_mutex_unlock(&g_printer_mutex);
		return ret;
	}
	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		DEBUG_OUT("printer sn in list is %s\n", (*tmp)->unique_flag);
		DEBUG_OUT("printer sn get is %s\n", unique_flag);
		if(strcmp((*tmp)->unique_flag, unique_flag) == 0)
		{
			DEBUG_OUT("Find %s int list\n", unique_flag);
			ret = 1;
			break;
		}
	}
	pthread_mutex_unlock(&g_printer_mutex);

	return ret;
}


int add_printer(const int type, const char* brand, const char *model, const char* ip, const char* unique_flag)
{
	printer_list_t *printer=NULL, *tmp=NULL;

	if(NULL==brand || NULL==model || NULL==ip || NULL==unique_flag)
	{
		return 0;
	}

	printer = (printer_list_t *)malloc(sizeof(printer_list_t));
	if(NULL == printer)
	{
		return 0;
	}

	printer->printer_type = type;
	strcpy(printer->printer_brand, brand);
	strcpy(printer->printer_model, model);
	strcpy(printer->printer_ip, ip);
	strcpy(printer->unique_flag, unique_flag);

	pthread_mutex_lock(&g_printer_mutex);
	if(g_printer_list)
	{
		tmp = g_printer_list;
		while(tmp->next)
		{
			tmp = tmp->next;
		}
		tmp->next = printer;
	}
	else
	{
		g_printer_list = printer;
	}
	printer->next = NULL;
	g_printer_count ++;
	pthread_mutex_unlock(&g_printer_mutex);

	return g_printer_count;
}

int del_printer(const char* unique_flag)
{
	printer_list_t *printer, **tmp;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		g_printer_count = 0;
		pthread_mutex_unlock(&g_printer_mutex);
		return 0;
	}

	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		if(strcmp((*tmp)->unique_flag, unique_flag) == 0)
		{
			printer = (*tmp);
			(*tmp) = (*tmp)->next;
			free(printer);
			g_printer_count --;
			break;
		}
	}
	pthread_mutex_unlock(&g_printer_mutex);

	return g_printer_count;
}

char* get_brand_of_printer(const char* unique_flag)
{
	printer_list_t **tmp = NULL;
	char* brand = NULL;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		pthread_mutex_unlock(&g_printer_mutex);
		return NULL;
	}

	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		if(strcmp((*tmp)->unique_flag, unique_flag) == 0)
		{
			brand = (*tmp)->printer_brand;
			break;
		}
	}
	pthread_mutex_unlock(&g_printer_mutex);

	return brand;
}

char* get_model_of_printer(const char* unique_flag)
{
	printer_list_t **tmp = NULL;
	char* model = NULL;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		pthread_mutex_unlock(&g_printer_mutex);
		return NULL;
	}

	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		if(strcmp((*tmp)->unique_flag, unique_flag) == 0)
		{
			model = (*tmp)->printer_model;
			break;
		}
	}
	pthread_mutex_unlock(&g_printer_mutex);

	return model;
}

char* get_ip_of_printer(const char* unique_flag)
{
	printer_list_t **tmp = NULL;
	char* ip = NULL;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		pthread_mutex_unlock(&g_printer_mutex);
		return NULL;
	}

	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		if(strcmp((*tmp)->unique_flag, unique_flag) == 0)
		{
			ip = (*tmp)->printer_ip;
			break;
		}
	}
	pthread_mutex_unlock(&g_printer_mutex);

	return ip;
}

int get_type_of_printer(const char *unique_flag)
{
	printer_list_t **tmp = NULL;
	int type = -1;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		pthread_mutex_unlock(&g_printer_mutex);
		return type;
	}

	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		if(strcmp((*tmp)->unique_flag, unique_flag) == 0)
		{
			type = (*tmp)->printer_type;
			break;
		}
	}
	pthread_mutex_unlock(&g_printer_mutex);

	return type;
}

int clear_printer_list()
{
	printer_list_t *printer, **tmp;

	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		g_printer_count = 0;
		pthread_mutex_unlock(&g_printer_mutex);
		return -1;
	}

	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		printer = (*tmp);
		if((*tmp)->next != NULL)
		{
			(*tmp) = (*tmp)->next;
		}
		free(printer);
		g_printer_count--;
	}

	g_printer_list = NULL;
	g_printer_count = 0;
	pthread_mutex_unlock(&g_printer_mutex);

	return g_printer_count;
}

int get_printer_count()
{
	pthread_mutex_lock(&g_printer_mutex);
	if(NULL == g_printer_list)
	{
		g_printer_count = 0;
	}
	pthread_mutex_unlock(&g_printer_mutex);
	return g_printer_count;
}


void serialize_printer_list(const char* buf)
{
	printer_list_t *printer, **tmp;
	printer_info_t info;
	int count = 0;
	memset(&info, 0x0, sizeof(printer_info_t));
	if(NULL == buf)
	{
		return;
	}
	pthread_mutex_lock(&g_printer_mutex);
	for(tmp=&g_printer_list; (*tmp)!=NULL; tmp=&(*tmp)->next)
	{
		printer = (*tmp);
		strcpy(info.printer_brand, printer->printer_brand);
		strcpy(info.printer_model, printer->printer_model);

		if(printer->printer_type == 0)
		{
			strcpy(info.printer_sn, printer->unique_flag);
		}
		else if(printer->printer_type == 1)
		{
			strcpy(info.printer_mac, printer->unique_flag);
		}
		else
		{

		}
		memcpy((void*)(buf+count*sizeof(printer_info_t)), &info, sizeof(printer_info_t));

		count ++;
		DEBUG_OUT("printer%d %s %s flag:%s\n", count, info.printer_brand, info.printer_model, info.printer_mac);
		memset(&info, 0x0, sizeof(printer_info_t));
	}
	pthread_mutex_unlock(&g_printer_mutex);
	return ;
}


int parse_uri_and_add_printer(const char* uri)
{
	printer_list_t printer;
	char tmp[256] = {0};
	int added = 0;

	if(NULL == uri)
	{
		return -1;
	}

	memset(&printer, 0x0, sizeof(printer));
	strcpy(tmp, uri);

	DEBUG_OUT("printer device_uri is %s\n", uri);
	//epson uri like this: usb://ZhongYing/NX-635KII?serial=xxxxxxxxx
	//hp uri like this:usb://HP/LaserJet_Professional_P1108?serial=xxxxxxxxx
	//network printer like this: socket://x.x.x.x/hp/LaserJet_Pro_MFP_M128fn?mac=xx-xx-xx-xx-xx
	const char* dim = ":/=?";
	char* token = strtok(tmp, dim);
	if(token != NULL)
	{
		if(strcasecmp(token, "usb") == 0)
		{
			printer.printer_type = 0;
		}
		else if(strcasecmp(token, "socket") == 0)
		{
			printer.printer_type = 1;
		}
	}
	if(printer.printer_type == 1)
	{
		token = strtok(NULL, dim);
		if(token != NULL)
		{
			strcpy(printer.printer_ip, token);
		}
	}
	token = strtok(NULL, dim);
	if(token != NULL)
	{
		strcpy(printer.printer_brand, token);
	}
	token = strtok(NULL, dim);
	if(token != NULL)
	{
		strcpy(printer.printer_model, token);
	}
	strtok(NULL, dim);
	token = strtok(NULL, dim);
	if(token != NULL)
	{
		strcpy(printer.unique_flag, token);
	}

	DEBUG_OUT("ADD printer to list...\n");
	add_printer(printer.printer_type, printer.printer_brand, printer.printer_model, printer.printer_ip, printer.unique_flag);
	DEBUG_OUT("%d printer in the list...\n", get_printer_count());
	added = 1;

	return added;
}


