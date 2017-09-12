#ifndef _PRINTER_H_
#define _PRINTER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push,1)

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

#pragma pack(pop)

/*functions*/
int check_printer_exist(const char* unique_flag);
int add_printer(const int type, const char* brand, const char *model, const char* ip, const char* unique_flag);
int del_printer(const char* unique_flag);
char* get_brand_of_printer(const char* unique_flag);
char* get_model_of_printer(const char* unique_flag);
int get_type_of_printer(const char *unique_flag);
char* get_ip_of_printer(const char *unique_flag);
int clear_printer_list();
int get_printer_count();
void serialize_printer_list(const char* buf);
int parse_uri_and_add_printer(const char* uri);

#ifdef __cplusplus
}
#endif

#endif /* PRINTER_H_ */
