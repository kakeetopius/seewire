.PHONY: clean

CC = gcc

CFLAGS = -g -std=c99 -D_DEFAULT_SOURCE -Wall -IIncludes 
LDLIBS = -lpcap

SRC = src/main.c src/arp.c src/dns.c src/ethernet.c src/ip4.c src/tcp.c src/udp.c src/http.c

OBJDIR = out
BIN = bin

OBJS = $(SRC:src/%.c=out/%.o)  

TARGET = bin/capture

$(TARGET) : $(OBJS) | BIN
	$(CC) -o $(TARGET) $(OBJS) $(LDLIBS)

out/%.o : src/%.c | OBJDIR
	$(CC) $(CFLAGS) -c $< -o $@ 

OBJDIR:
	@mkdir -p $(OBJDIR)

BIN:
	@mkdir -p $(BIN)

clean:
	@rm -rf $(BIN)
