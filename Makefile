CC := clang
CFLAGS := -Wall -Werror -fPIC -DDER_TAG_SIZE=1 -Wno-pointer-to-int-cast

LIB_NAME := libchoma

SRC_DIR := src
BUILD_DIR := build
OUTPUT_DIR := output
HEADER_OUTPUT_DIR := $(OUTPUT_DIR)/include
TESTS_SRC_DIR := tests
TESTS_BUILD_DIR := $(BUILD_DIR)/tests
TESTS_OUTPUT_DIR := $(OUTPUT_DIR)/tests

LIB_DIR := $(OUTPUT_DIR)/lib
TESTS_DIR := build/tests

STATIC_LIB := $(LIB_DIR)/$(LIB_NAME).a
DYNAMIC_LIB := $(LIB_DIR)/$(LIB_NAME).dylib

SRC_FILES := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/external/libDER/*.c)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))

TESTS_SUBDIRS := $(wildcard $(TESTS_SRC_DIR)/*)
TESTS_BINARIES := $(patsubst $(TESTS_SRC_DIR)/%,$(TESTS_OUTPUT_DIR)/%,$(TESTS_SUBDIRS))

CHOMA_HEADERS_SRC_DIR := $(SRC_DIR)
CHOMA_HEADERS_DST_DIR := $(HEADER_OUTPUT_DIR)/choma
DER_HEADERS_SRC_DIR := $(SRC_DIR)/external/libDER
DER_HEADERS_DST_DIR := $(HEADER_OUTPUT_DIR)/libDER

CHOMA_HEADERS := $(shell find $(CHOMA_HEADERS_SRC_DIR) -type f -name "*.h")
DER_HEADERS := $(shell find $(DER_HEADERS_SRC_DIR) -type f -name "*.h")

all: $(STATIC_LIB) $(DYNAMIC_LIB) copy-headers $(TESTS_BINARIES)

$(STATIC_LIB): $(OBJ_FILES)
	@mkdir -p $(LIB_DIR)
	ar rcs $@ $^

$(DYNAMIC_LIB): $(OBJ_FILES)
	@mkdir -p $(LIB_DIR)
	$(CC) $(CFLAGS) -shared -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -Isrc/external -o $@

$(TESTS_OUTPUT_DIR)/%: $(TESTS_SRC_DIR)/%
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(OUTPUT_DIR)/include -o $@ $</*.c -L$(LIB_DIR) -lchoma

copy-headers: copy-choma-headers copy-DER-headers

copy-choma-headers: $(CHOMA_HEADERS)
	rm -rf $(CHOMA_HEADERS_DST_DIR)
	@mkdir -p $(CHOMA_HEADERS_DST_DIR)
	cp $^ $(CHOMA_HEADERS_DST_DIR)

copy-DER-headers: $(DER_HEADERS)
	rm -rf $(DER_HEADERS_DST_DIR)
	@mkdir -p $(DER_HEADERS_DST_DIR)
	cp $^ $(DER_HEADERS_DST_DIR)

clean:
	rm -rf $(OUTPUT_DIR)/*.a $(OUTPUT_DIR)/*.dylib $(BUILD_DIR)/*