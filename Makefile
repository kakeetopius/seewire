CC = gcc

CFLAGS = -g -std=c99 -D_DEFAULT_SOURCE -Wall -IIncludes 
LDFLAGS = -L./Lib -Wl,-rpath=../Lib
LDLIBS = -llist -lpcap

SRC = src/main.c

OBJDIR = out
BIN = bin

OBJS = out/main.o

TARGET = bin/capture

$(TARGET) : $(OBJS) | BIN
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS) $(LDLIBS)

out/%.o : src/%.c | OBJDIR
	$(CC) $(CFLAGS) -c $< -o $@ 

OBJDIR:
	@mkdir -p $(OBJDIR)

BIN:
	@mkdir -p $(BIN)

