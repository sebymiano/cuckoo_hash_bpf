# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
SHELL := /bin/bash
PKG_CONFIG := pkg-config
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBGREATEST_SRC := $(abspath ../greatest)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_OBJ_SHARED := $(abspath $(OUTPUT)/libbpf.so)
LIBBPF_PKGCONFIG := $(abspath $(OUTPUT)/pkgconfig)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
TEST_BIN := $(abspath ./cuckoo_test)
TEST_USR_BIN := $(abspath ./cuckoo_test_usr)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
USR_LIB_NAME := libcuckoo
USR_LIB_SRC := $(abspath ./usr-lib/cuckoo_usr.c)
USR_LIB_DIR := $(abspath ./usr-lib)
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(LIBGREATEST_SRC) -I$(USR_LIB_DIR)
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

USR_LIB_CFLAGS := -Wall -Werror -fpic
USR_LIB_INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I../libbpf/include

APPS = cuckoo_test cuckoo_test_usr

# CUCKOO_CONFIG_DEPS = # Add here other libraries
# CUCKOO_PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(CUCKOO_CONFIG_DEPS))
# CUCKOO_PKG_LIBS := $(shell $(PKG_CONFIG) --static --libs $(CUCKOO_CONFIG_DEPS))

INCLUDES += $(CUCKOO_PKG_CFLAGS)
ALL_LDFLAGS += -lrt -ldl -lpthread -lm $(CUCKOO_PKG_LIBS) $(abspath $(OUTPUT))/$(USR_LIB_NAME).a

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: usr-lib-static usr-lib-shared $(APPS) 

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)
	$(Q)rm -rf $(USR_LIB_NAME).a $(USR_LIB_NAME).so

clean-app:
	$(call msg,CLEAN-APP)
	$(Q)rm -rf $(APPS)
	$(Q)rm -rf $(OUTPUT)/*.skel.h
	$(Q)rm -rf $(OUTPUT)/*.o

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) 	      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
$(OUTPUT)/%.bpf.o: ebpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard ebpf/%.h) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -Wno-address-of-packed-member -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

usr-lib-static: $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,USR-LIB-STATIC,$@)
	$(CC) $(USR_LIB_CFLAGS) $(USR_LIB_INCLUDES) -c $(USR_LIB_SRC) -o $(OUTPUT)/$(USR_LIB_NAME).o
	ar -rcs $(OUTPUT)/$(USR_LIB_NAME).a $(OUTPUT)/$(USR_LIB_NAME).o

usr-lib-shared: $(OUTPUT) $(LIBBPF_OBJ)
	$(call msg,USR-LIB-SHARED,$@)
	$(CC) $(USR_LIB_CFLAGS) $(USR_LIB_INCLUDES) -shared $(USR_LIB_SRC) -o $(OUTPUT)/$(USR_LIB_NAME).so $(LIBBPF_OBJ_SHARED)

test:
	$(call msg,TEST,$@)
	$(Q)$(MAKE) clean
	$(Q)$(MAKE) cuckoo_test -j4
	sudo $(TEST_BIN) -v | $(LIBGREATEST_SRC)/contrib/greenest

test-usr-lib:
	$(call msg,TEST-USR,$@)
	$(Q)$(MAKE) clean
	$(Q)$(MAKE) usr-lib-static usr-lib-shared
	$(Q)$(MAKE) cuckoo_test_usr -j4
	sudo $(TEST_USR_BIN) -v | $(LIBGREATEST_SRC)/contrib/greenest

format:
	clang-format -style=file -i *.[ch]
	clang-format -style=file -i usr-lib/*.[ch]
	clang-format -style=file -i ebpf/*.[ch] ebpf/lib/*.[ch]
	@grep -n "TODO" *.[ch] || true

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: