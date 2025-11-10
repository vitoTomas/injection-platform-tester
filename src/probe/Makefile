#
# eBPF program/probe target.
#
ifdef BUILD
ifndef INCLUDE_BPF
$(error "Missing include path in INCLUDE_BPF")
endif

ifndef INCLUDE_LINUX
$(error "Missing include path in INCLUDE_LINUX")
endif
endif

CC := clang
CFLAGS ?= -O2 -g -target bpf
SRC ?= bpf.c
OBJ ?= bpf.o

build:
	$(CC) $(CFLAGS) -I$(INCLUDE_BPF) -I$(INCLUDE_LINUX) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)
