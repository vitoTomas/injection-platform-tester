ifdef BUILD
ifndef INCLUDE_BPF
$(error "Missing path in INCLUDE_BPF")
endif

ifndef INCLUDE_SKEL
$(error "Missing path in INCLUDE_SKEL")
endif

ifndef LIB
$(error "Missing path in LIB")
endif
endif

CC := clang

CFLAGS ?= -O2 -Wall -Werror -lelf -lz
CFLAGS_LD ?= -O2 -Wall -Werror

SRC ?= ipt.c
SRC_LD ?= loader.c

OBJ ?= ipt
OBJ_LD ?= loader.o

loader:
	$(CC) $(CFLAGS_LD) -I$(INCLUDE_BPF) -I$(INCLUDE_SKEL) -c $(SRC_LD) -o $(OBJ_LD)

build: loader
	$(CC) $(CFLAGS) -I$(INCLUDE_BPF) -I$(INCLUDE_SKEL) $(SRC) $(OBJ_LD) $(LIB) -o $(OBJ)

clean:
	rm -f $(OBJ)
	rm -f loader.o
