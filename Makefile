#SRCS = $(wildcard *.c)

SRCS=util.c \
	 md5.c \
	 app_comm.c \
	 server_comm.c \
	 http_load.c \
	 databuffer.c \
	 printer.c \
	 print-server.c

OBJS = $(SRCS:.c=.o)

CC = gcc

INCLUDES = -I./ -I/usr/includes

LIBS =-lpthread -levent -L/usr/local/lib -lusb-1.0

CCFLAGS = -g -Wall -O0 -Bstatic

print-server: $(OBJS)
	$(CC) $(CCFLAGS) $^ -o $@ $(INCLUDES) $(LIBS)


clean:
	rm *.o print-server


.PHONY:
	clea
