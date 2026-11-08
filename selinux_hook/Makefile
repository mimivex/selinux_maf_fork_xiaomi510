SELINUX_VERSION := 1.1.9.2

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

OS_NAME = $(shell uname | tr A-Z a-z)
MACHINE = $(shell uname -m)
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(OS_NAME)-$(MACHINE)/bin
ifdef ANDROID_NDK_LATEST_HOME
    NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
    NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK_HOME
    NDK_PATH ?= $(ANDROID_NDK_HOME)/$(NDK_BIN_DIR)
endif

ifdef TARGET_COMPILE
    CC := $(TARGET_COMPILE)gcc
    LD := $(TARGET_COMPILE)ld
    OBJCOPY := $(TARGET_COMPILE)objcopy
else ifdef NDK_PATH
    CC := $(NDK_PATH)/aarch64-linux-android31-clang
    LD := $(NDK_PATH)/ld.lld
    OBJCOPY := $(NDK_PATH)/llvm-objcopy
endif

CFLAGS = -Wall -O0 \
    -ffreestanding \
    -fno-inline \
    -fno-builtin \
    -fno-strict-aliasing \
    -fno-PIC \
    -fno-pie \
    -fno-asynchronous-unwind-tables \
    -fno-unwind-tables \
    -fno-stack-protector \
    -fno-common \
    -fno-exceptions

CFLAGS += -DSELINUX_VERSION=\"$(SELINUX_VERSION)\"
CFLAGS += -std=gnu99
CFLAGS += $(EXTRA_CFLAGS)

INCLUDE_DIRS := . include patch/include linux linux/include linux/security/selinux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := selinux_hook.o

# Rebuild when the extra flags change, so a 'make debug' object can never be
# relinked under the normal name.
.buildflags: FORCE
	@printf '%s\n' '$(EXTRA_CFLAGS)' > $@.tmp; \
	if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

$(objs): .buildflags

all: selinux_hook_$(SELINUX_VERSION).kpm

selinux_hook_$(SELINUX_VERSION).kpm: ${objs}
	${CC} -r -nostdlib -Wl,--no-eh-frame-hdr -o $@ $^
ifneq ($(strip $(OBJCOPY)),)
	${OBJCOPY} --remove-section=.eh_frame --remove-section=.eh_frame_hdr --remove-section=.rela.eh_frame $@
endif

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean debug debug-noredirect debug-snapshotonly FORCE
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f

# Diagnostic build: same module plus DIAG tracing around the rare hooks and a
# stall watchdog that fires sysrq t/l when the kernel stops making progress.
# Produces selinux_hook_$(SELINUX_VERSION)-debug.kpm (KPM version 1.1.9.2-debug)
# and leaves the normal build in place.
debug:
	$(MAKE) EXTRA_CFLAGS="-DSELINUX_DIAG_TRACE=1 -DSELINUX_DIAG_WATCHDOG=1" all
	cp selinux_hook_$(SELINUX_VERSION).kpm selinux_hook_$(SELINUX_VERSION)-debug.kpm
	$(MAKE) all

# Bisect build: same hooks and DIAG tracing, but the clean-policydb snapshot and
# the per-task clean-eval scope are compiled out, so every AV computation runs
# on the live policydb.  Tells us whether the freeze comes from the redirect or
# from merely having the hooks installed.
debug-noredirect:
	$(MAKE) EXTRA_CFLAGS="-DSELINUX_DIAG_TRACE=1 -DSELINUX_DIAG_WATCHDOG=1 -DSELINUX_DIAG_NO_REDIRECT=1" all
	cp selinux_hook_$(SELINUX_VERSION).kpm selinux_hook_$(SELINUX_VERSION)-debug-noredirect.kpm
	$(MAKE) all

# Bisect level 3: the clean policydb is still snapshotted, but no task enters a
# clean-eval scope, so nothing ever hands the clean policydb to
# context_struct_compute_av().  Separates "building the clean policydb" from
# "redirecting callers onto it".
debug-snapshotonly:
	$(MAKE) EXTRA_CFLAGS="-DSELINUX_DIAG_TRACE=1 -DSELINUX_DIAG_WATCHDOG=1 -DSELINUX_DIAG_SNAPSHOT_ONLY=1" all
	cp selinux_hook_$(SELINUX_VERSION).kpm selinux_hook_$(SELINUX_VERSION)-debug-snapshotonly.kpm
	$(MAKE) all