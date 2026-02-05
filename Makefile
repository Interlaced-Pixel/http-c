# Makefile for HTTP-C single-header library

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -std=c99
LDFLAGS =

# Source files
EXAMPLE_SRCS = example.c

# Object files
EXAMPLE_OBJS = $(EXAMPLE_SRCS:.c=.o)

# Targets
EXAMPLE = example

.PHONY: all clean

all: $(EXAMPLE)

$(EXAMPLE): $(EXAMPLE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXAMPLE_OBJS) $(EXAMPLE)