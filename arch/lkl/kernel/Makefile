extra-y := vmlinux.lds

obj-y = setup.o threads.o irq.o time.o syscalls.o misc.o console.o \
	syscalls_32.o cpu.o match.o module.o glue_helper.o

KBUILD_CFLAGS += -DCONFIG_X86_64

CFLAGS_module.o = -g -O0
