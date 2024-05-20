CC := clang

CFLAGS ?= -Wall -Werror $(shell pkg-config --cflags libcrypto) -fPIC -Wno-pointer-to-int-cast -Wno-unused-command-line-argument -Wno-deprecated-declarations -framework CoreFoundation
LDFLAGS ?= 
DYLIB_LDFLAGS ?= 

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -fsanitize=address -static-libsan
endif
DISABLE_SIGNING ?= 0
DISABLE_TESTS ?= 0

LIB_NAME := libchoma
INSTALL_PATH ?= /usr/local/

ifeq ($(TARGET), ios)
BUILD_DIR := build/ios
OUTPUT_DIR := output/ios
CFLAGS += -arch arm64 -arch arm64e -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=11.0
ifeq ($(DISABLE_SIGNING), 0)
CFLAGS += external/ios/libcrypto.a
endif
else
BUILD_DIR := build
OUTPUT_DIR := output
ifeq ($(DISABLE_SIGNING), 0)
CFLAGS += $(shell pkg-config --libs libcrypto)
endif
CFLAGS += -mmacosx-version-min=10.13
endif

ifeq ($(DISABLE_SIGNING), 1)
CFLAGS += -DDISABLE_SIGNING=1
endif

SRC_DIR := src

HEADER_OUTPUT_DIR := $(OUTPUT_DIR)/include
TESTS_SRC_DIR := tests
TESTS_BUILD_DIR := $(BUILD_DIR)/tests
TESTS_OUTPUT_DIR := $(OUTPUT_DIR)/tests

LIB_DIR := $(OUTPUT_DIR)/lib
TESTS_DIR := build/tests

STATIC_LIB := $(LIB_DIR)/$(LIB_NAME).a
DYNAMIC_LIB := $(LIB_DIR)/$(LIB_NAME).dylib

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))

ifeq ($(DISABLE_TESTS), 0)
TESTS_SUBDIRS := $(wildcard $(TESTS_SRC_DIR)/*)
TESTS_BINARIES := $(patsubst $(TESTS_SRC_DIR)/%,$(TESTS_OUTPUT_DIR)/%,$(TESTS_SUBDIRS))
endif

CHOMA_HEADERS_SRC_DIR := $(SRC_DIR)
CHOMA_HEADERS_DST_DIR := $(HEADER_OUTPUT_DIR)/choma

CHOMA_HEADERS := $(shell find $(CHOMA_HEADERS_SRC_DIR) -type f -name "*.h")

all: $(STATIC_LIB) $(DYNAMIC_LIB) copy-choma-headers clean-test $(TESTS_BINARIES)

$(STATIC_LIB): $(OBJ_FILES)
	@mkdir -p $(LIB_DIR)
	libtool $^ -o $@

ifeq ($(TARGET), ios)
$(DYNAMIC_LIB): $(OBJ_FILES)
	@mkdir -p $(LIB_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DYLIB_LDFLAGS) -shared -o $@ $^
	@ldid -S $@
else
$(DYNAMIC_LIB): $(OBJ_FILES)
	@mkdir -p $(LIB_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DYLIB_LDFLAGS) -shared -o $@ $^
endif

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

ifeq ($(DISABLE_TESTS), 0)
ifeq ($(TARGET), ios)
$(TESTS_OUTPUT_DIR)/%: $(TESTS_SRC_DIR)/%
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(CC) $(CFLAGS) $(LDFLAGS) -I$(OUTPUT_DIR)/include -o $@ $</*.c $(OUTPUT_DIR)/lib/libchoma.a
	@ldid -Sexternal/ios/entitlements.plist $@
else
$(TESTS_OUTPUT_DIR)/%: $(TESTS_SRC_DIR)/%
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(CC) $(CFLAGS) $(LDFLAGS) -I$(OUTPUT_DIR)/include -o $@ $</*.c $(OUTPUT_DIR)/lib/libchoma.a
endif
endif

copy-choma-headers: $(CHOMA_HEADERS)
	@rm -rf $(CHOMA_HEADERS_DST_DIR)
	@mkdir -p $(CHOMA_HEADERS_DST_DIR)
	@cp $^ $(CHOMA_HEADERS_DST_DIR)

clean-all: clean clean-output

clean: clean-test
	@rm -rf $(BUILD_DIR)/*

clean-test:
	@rm -rf $(OUTPUT_DIR)/tests/*

clean-output:
	@rm -rf $(OUTPUT_DIR)/*

install: all
	@mkdir -p $(INSTALL_PATH)/include
	@rm -rf $(INSTALL_PATH)/include/choma
	@cp -r $(OUTPUT_DIR)/include/choma $(INSTALL_PATH)/include
	@rm -rf $(INSTALL_PATH)/lib/libchoma.*
	@cp -r $(OUTPUT_DIR)/lib $(INSTALL_PATH)
