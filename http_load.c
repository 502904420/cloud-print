#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "util.h"

#define RECV_BUF_LEN (1024*100)

struct hostent *host;
char domain[256] = {0};
int port = 0;

int get_status(char *recv_buf)
{
	if(NULL == recv_buf)
	{
		printf("recv_buf is NULL\n");
		return -1;
	}

	int http_status = 0;
	char line[256] = {0} ;
	char *rest ;

	rest = strstr(recv_buf,"\r\n");
	if ( rest != NULL)
	{
		memcpy(line, recv_buf, rest - recv_buf);
		if(strstr(line,"200"))
		{
			http_status = 200;
		}
		else if(strstr(line,"302") || strstr(line,"301"))
		{
			http_status = 302;
		}
		else
		{
			http_status = -1;
		}
	}

	return http_status;
}

char *refresh_url(char *recv_buf)
{
	char *rest = NULL;
	char *new_url = NULL;
	char *line = NULL;

	if(NULL == recv_buf)
	{
		return NULL;
	}

	new_url = (char *)malloc(RECV_BUF_LEN);
	if(NULL == new_url)
	{
		printf("malloc new_url error!\n");
		return NULL;
	}

	if( strstr(recv_buf,"Location:") == NULL)
	{
		return NULL;
	}
	else
	{
		rest = strstr(recv_buf,"Location:")+strlen("location: ");
		line = strstr(rest,"\r\n");
		memcpy(new_url, rest,line-rest);
	}

	return new_url;
}

long get_file_size(char *recv_buf)
{
	long file_size = 0;
	char *rest = NULL;
	char *line = NULL;
	char actual_size[RECV_BUF_LEN] = {0} ;
	if( NULL == recv_buf)
	{
		printf("recv %s is NULL\n",recv_buf);
		return -1;
	}

	if((strstr(recv_buf,"Content-Length")) == NULL)
	{
		 printf("Content-Length is NULL\n");
		 return -1;
	}
	rest = strstr(recv_buf,"Content-Length:")+strlen("Content-Length: ");
	line = strstr(rest,"\r\n");

	memcpy(actual_size,rest,line-rest);
	file_size = atoi(actual_size);
		
	 return file_size;
}

char *down_local_file(char *src)
{
	if(NULL == src)
	{
		return NULL;
	}

	char *line = NULL;
	char file[100] = {0};
	char *content = NULL;
	char *file_name;
	int len = 0;
	if(strstr(src,"Content-Disposition") == 0)
	{
		return NULL;
	}
	else
    {
		file_name = (char *)malloc(1024);
		if(NULL == file_name)
		{
			return NULL;
		}
		line = strstr(src,"filename=") + 9;

		if( NULL != line)
	    {
			content = strstr(line,"\r\n");
			if( content != NULL)
			{
			  len = strlen(line) - strlen(content);
			  memcpy(file_name,line,len);
			  line[len] = 0;
			}
		 }
    }

	return file_name;
}


char *down_file(char *src, char c)
{
	if(NULL == src)
	{
		printf("The src %s is null\n",src);
		exit(-1);
	}

	int len = 0;
	len = strlen(src);

	while(src[len-1])
	{
		if( strchr(src + (len - 1),c))
		{
			return (src + (len - 1));
		}
		else
		{
			len--;
		}
	}

	return NULL;

}


char *http_request(char *url)
{
	char *url_dress = NULL;
	char *file_dress = NULL;
	char *ret = NULL;
	char *request;
	struct hostent *host;

	url_dress = url+strlen("http://");
	DEBUG_OUT("url address is %s\n", url_dress);
	file_dress = strchr(url_dress, '/');
	DEBUG_OUT("file address is %s\n", file_dress);
	if (file_dress)
	{
		//DEBUG_OUT("domain is %s\n", )
		memcpy(domain, url_dress, file_dress-url_dress);
	}

	ret = strstr(domain,":");
	if(ret)
	{
		port = atoi(ret);
	}
	else
	{
		port = 80;
	}

	request = (char *)malloc(RECV_BUF_LEN);
	if(NULL == request)
	{
		printf("malloc request error!\n");
		exit(-1);
	}

	sprintf(request,
			"GET %s HTTP/1.1\r\n"
			"Host:%s\r\n"
			"User-Agent:Mozilla/5.0(X11;Linux_x86_64;rv:45.0) Gecko/20100101 Firefox/45.0\r\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
			"Accept-Language: zh-CN,zh;q=0.5\r\n"
			"Accept-Encoding: gzip,deflate\r\n"
			"Connection: keep-alive\r\n\r\n",
			file_dress, domain);
	//DEBUG_OUT("%s\n", request);

	return request;
}

int start_download(const char *load_addr, const char* save_file)
{
	char *url;
	char *buffer;
	char *head_buffer = NULL;
	char header[RECV_BUF_LEN] = {0};
	char *file_name = NULL;
	char *local_file = NULL;
	char *request = NULL;
	struct sockaddr_in server_addr;
	struct timeval start_time, end_time;
	FILE *fp = NULL;
	int fd;
	int status = -1;
	int send = 0;
	int total_send = 0;
	int length = 0;
	int http_status = 0;
	float timeuse;

	if(NULL == load_addr)
	{
		DEBUG_OUT("download addr is NULL\n");
		return -1;
	}
	if(NULL == save_file)
	{
		file_name = "print-server";
	}
	else
	{
		file_name = save_file;
	}

	url = load_addr;

	while(url != NULL)
	{
		request = http_request(url);
		//DEBUG_OUT("%s\n", request);

		host = gethostbyname(domain);
		if(NULL == host)
		{
			DEBUG_OUT("Get host name error!\n");
			return -1;
		}

		gettimeofday(&start_time, NULL);

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if(fd == -1)
		{
			DEBUG_OUT("Socket error!\n");
			return -1;
		}
		bzero(&server_addr,sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(port);
		server_addr.sin_addr = *((struct in_addr *)host->h_addr);
		status = connect(fd, (struct sockaddr *)(&server_addr),sizeof(struct sockaddr));
		if(status < 0)
		{
			DEBUG_OUT("connect error!\n");
			return -1;
		}

		send = 0;
		total_send = 0;
		length = strlen(request);
		while(total_send < length)
		{
			send = write(fd, request + total_send, length - total_send);
			if (send == -1)
			{
				DEBUG_OUT("send error!\n");
				return -1;
			}
			total_send += send;
			DEBUG_OUT("%d bytes send OK!\n", total_send);
		}

		buffer = (char *)malloc(RECV_BUF_LEN);

		long file_size = 0;
		int mark = 1;
		int count=0;
		while(length > 0)
		{
			DEBUG_OUT("load file ....\n");
			memset(buffer, 0, RECV_BUF_LEN);
			length = recv(fd, buffer, RECV_BUF_LEN, 0);
			if(mark > 0)
			{
				mark = 0;
				//DEBUG_OUT("buffer is %s\n", buffer);
				head_buffer = strstr(buffer, "\r\n\r\n")+4;
				memcpy(header, buffer, head_buffer-buffer);
				//DEBUG_OUT("%s\n",header);
				file_size = get_file_size(header);
				http_status = get_status(header);
				if(http_status == 200)
				{
					//file_name = down_local_file(header);
					//file_name == save_file;
					DD("download file name is %s\n", file_name);
					if(NULL == file_name)
					{
						file_name = down_file(url, '/') + 1;
						fp = fopen(file_name, "w");
						if(NULL == fp)
						{
							DEBUG_OUT("open file %s failed!",local_file);
							return -1;
						}
					}
					else
					{
						fp = fopen(file_name,"w");
						if(NULL == fp)
						{
							DEBUG_OUT("open file %s failed!",local_file);
							return -1;
						}
					}

					count = fwrite(head_buffer, 1, length-(head_buffer - buffer), fp);
					DEBUG_OUT("%s\t%d\n", head_buffer, strlen(head_buffer));
					DEBUG_OUT("head_buffer %s\n", head_buffer);
					DEBUG_OUT("--------------\n");
					url = NULL;
				}
				else if(http_status == 302)
				{
					DEBUG_OUT("http status is 302, redirect...\n");
					url = refresh_url(header);
				}
			}
			else
			{
				//DEBUG_OUT("write %d bytes...\n", length);
				fwrite(buffer, 1, length, fp);
				fflush(fp);
				count += length;
			}

			if(count == file_size)
			{
				DD("download OK...\n");
				break;
			}
		}

		DEBUG_OUT("total:%d\n",count);
		free(request);
		free(buffer);
		close(fd);
	}

	gettimeofday(&end_time, NULL);
	timeuse = 1000000*(end_time.tv_sec - start_time.tv_sec) + end_time.tv_usec - start_time.tv_usec;
	timeuse /= 1000000;
	DEBUG_OUT("Used time: %f\n",timeuse);
	fclose(fp);
	//free(url);

	return 0;
}













