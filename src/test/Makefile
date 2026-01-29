CC := clang
CFLAGS ?= -O2 -Wall -Werror
INJ_CFLAGS ?= -shared -fPIC -Wl,--no-undefined -Wl,--strip-all
SRC ?= test.c
INJ_SRC ?= injectable.c
OBJ ?= test
INJ_OBJ ?= injectable.so

build:
	$(CC) $(CFLAGS) $(SRC) -o $(OBJ)
	$(CC) $(INJ_CFLAGS) $(INJ_SRC) -o $(INJ_OBJ)

clean:
	rm -f $(OBJ)
	rm -f $(INJ_OBJ)
