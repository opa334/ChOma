.PHONY: all clean
CC=gcc
SOURCES=*.c lib/include/libDER/*.c
OUTPUT=build/MachO_main
CFLAGS=-Ilib/include -DDER_TAG_SIZE=8

all: parser

clean:
	@rm -rf build/*

parser: $(SOURCES)
	@mkdir -p build
	@$(CC) $(CFLAGS) -o $(OUTPUT) $(SOURCES)