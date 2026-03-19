CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lssl -lcrypto -largon2
TARGET = stk
SRCS = main.c codec.c huffman.c buffer.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
