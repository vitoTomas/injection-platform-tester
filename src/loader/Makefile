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
SRC ?= loader.c
OBJ ?= loader

build:
	$(CC) $(CFLAGS) -I$(INCLUDE_BPF) -I$(INCLUDE_SKEL) $(SRC) $(LIB) -o $(OBJ)

clean:
	rm -f $(OBJ)
