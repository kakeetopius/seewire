.PHONY: clean

CC = gcc

CFLAGS = -g -std=c99 -D_DEFAULT_SOURCE -Wall -IIncludes -MMD -MP
LDLIBS = -lpcap

SRC = src/main.c src/arp.c src/dns.c src/datalink.c src/ip4.c src/tcp.c src/udp.c src/http.c

OBJDIR = out
BIN = bin

OBJS = $(SRC:src/%.c=out/%.o)  
DEPENDECIES = $(OBJS:%.o=%.d)

TARGET = bin/seewire

all: $(TARGET)

$(TARGET) : $(OBJS) | BIN
	$(CC) -o $(TARGET) $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o : src/%.c | OBJDIR
	$(CC) $(CFLAGS) -c $< -o $@ 

OBJDIR:
	@mkdir -p $(OBJDIR)

BIN:
	@mkdir -p $(BIN)

clean:
	@rm -rf $(BIN) $(OBJDIR)

-include $(DEPENDECIES)
