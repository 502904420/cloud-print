/*
 * util.h
 *
 *  Created on: Nov 3, 2016
 *      Author: root
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>

#ifdef __ANDROID__
	#include <android/log.h>
	#define DD(...) __android_log_print(ANDROID_LOG_DEBUG, "print-server", __VA_ARGS__)
	#define BOX
	#define DEBUG_OUT(...) printf(__VA_ARGS__)
#else
	#define DD(...)		printf(__VA_ARGS__)
	#define DEBUG_OUT(...) printf(__VA_ARGS__)
#endif


#ifdef DEBUG
#define ASSERT(e,s) ((!(e)) ? \
		printf("**ASSERT!: FILE: %s FUNC: %s Ln: %4d <"#e">.\r\n%s\r\n", __FILE__, __FUNCTION__, __LINE__, (s)): \
		(void) 0)
#else
#define ASSERT(e, s)
#endif

#define WARNING(s) printf("***WARN!:FILE:%s FUNC:%s Ln:%4d ,%s>.\r\n", __FILE__, __FUNCTION__, __LINE__, s)


#define SWAP16(data) \
	((((data) & 0x00FF) << 8) | \
	(((data) & 0xFF00) >> 8))

#define SWAP32(data) \
	((((data) & 0x000000FF) << 24) | \
	(((data) & 0x0000FF00) << 8) | \
	(((data) & 0x00FF0000) >> 8) | \
	(((data) & 0xFF000000) >> 24))

/*functions*/
char calc_bcc_checksum(void *frame, int frame_length);
int check_frame(void *frame, int length);

int get_sn_of_device(const char* serial_number);
int get_version_of_system(const char* sys_version);

int change_byte_array_to_string(char array[], int array_count, char* out_string);

int compare_version(const char *version);
void update_program(void *load_addr);

int check_ip_address(const char* addr);

#endif /* UTIL_H_ */
