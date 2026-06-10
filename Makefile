#
# Libbpf target.
#

LIBBPF_SRC := libbpf/src
LIBBPF_PREFIX := /
LIBBPF_LIBDIR := $(LIBBPF_PREFIX)/lib
LIBBPF_INCLUDEDIR := $(LIBBPF_PREFIX)/include
LIBBPF_UAPIDIR := $(LIBBPF_INCLUDEDIR)
LIBBPF_INCLUDE := $(shell pwd)/libbpf/src/root/$(LIBBPF_INCLUDEDIR)
LIBBPF_LIB := $(shell pwd)/libbpf/src/root/$(LIBBPF_LIBDIR)

libbpf:
	mkdir -p $(LIBBPF_SRC)/build $(LIBBPF_SRC)/root
	make BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root \
	PREFIX=$(LIBBPF_PREFIX) LIBDIR=$(LIBBPF_LIBDIR) \
	INCLUDEDIR=$(LIBBPF_INCLUDEDIR) UAPIDIR=$(LIBBPF_UAPIDIR) \
	-C $(LIBBPF_SRC) install

libbpf-clean:
	make -C libbpf/src clean
	rm -rf $(LIBBPF_SRC)/build $(LIBBPF_SRC)/root

#
# Bpftool target.
#

BPFTOOL_SRC := bpftool/src
BPFTOOL_OUTDIR := $(shell pwd)/bpftool/out/
BPFTOOL_VMLINUX := $(shell pwd)/bpftool/out/vmlinux.h
BPFTOOL_INCLUDE := $(shell pwd)/bpftool/out/vmlinux
BPFTOOL_BIN := $(shell pwd)/bpftool/out/bpftool

bpftool:
	mkdir -p $(BPFTOOL_OUTDIR) $(BPFTOOL_INCLUDE)
	ln -fs $(BPFTOOL_BIN) bpftool.ln
	make OUTPUT=$(BPFTOOL_OUTDIR) -C $(BPFTOOL_SRC)
	cp $(BPFTOOL_VMLINUX) $(BPFTOOL_INCLUDE)
	
bpftool-clean:
	make -C $(BPFTOOL_SRC) clean
	rm -rf $(BPFTOOL_OUTDIR)
	rm -f bpftool.ln

#
# eBPF probe target.
#

BUILDDIR := build
BUILDDIR_FULL := $(shell pwd)/$(BUILDDIR)
BPF_SRC := $(shell pwd)/src/probe/bpf_signal.c
BPF_OBJ := $(shell pwd)/$(BUILDDIR)/bpf_signal.o
BPF_SRC_EXE := $(shell pwd)/src/probe/bpf_execve.c
BPF_OBJ_EXE := $(shell pwd)/$(BUILDDIR)/bpf_execve.o

bpf: libbpf bpftool
	mkdir -p $(BUILDDIR)
	make BUILD=y INCLUDE_BPF=$(LIBBPF_INCLUDE) \
	INCLUDE_LINUX=$(BPFTOOL_INCLUDE) SRC=$(BPF_SRC) OBJ=$(BPF_OBJ) \
	-C src/probe build;
	make BUILD=y INCLUDE_BPF=$(LIBBPF_INCLUDE) \
	INCLUDE_LINUX=$(BPFTOOL_INCLUDE) SRC=$(BPF_SRC_EXE) OBJ=$(BPF_OBJ_EXE) \
	-C src/probe build;
	./bpftool.ln gen skeleton $(BPF_OBJ) > \
	$(BUILDDIR)/$(notdir $(basename $(BPF_OBJ))).h;
	./bpftool.ln gen skeleton $(BPF_OBJ_EXE) > \
	$(BUILDDIR)/$(notdir $(basename $(BPF_OBJ_EXE))).h;

bpf-clean:
	make OBJ=$(BPF_OBJ) -C src/probe clean;
	make OBJ=$(BPF_OBJ_EXE) -C src/probe clean;
	rm $(BUILDDIR)/$(notdir $(basename $(BPF_OBJ))).h;
	rm $(BUILDDIR)/$(notdir $(basename $(BPF_OBJ_EXE))).h;

#
# Loader target.
#

LOADER_OBJ := $(shell pwd)/$(BUILDDIR)/ipt

loader: bpf
	make BUILD=y INCLUDE_BPF=$(LIBBPF_INCLUDE) INCLUDE_SKEL=$(BUILDDIR_FULL) \
	LIB=$(LIBBPF_LIB)/libbpf.a OBJ=$(LOADER_OBJ) -C src/loader build

loader-clean:
	make OBJ=$(LOADER_OBJ) -C src/loader clean

#
# Test target.
#

TEST_OBJ := $(shell pwd)/build/test
TEST_INJ_OBJ := $(shell pwd)/build/injectable.so

test:
	make OBJ=$(TEST_OBJ) INJ_OBJ=$(TEST_INJ_OBJ) -C src/test build
test-clean:
	make OBJ=$(TEST_OBJ) INJ_OBJ=$(TEST_INJ_OBJ) -C src/test clean

#
# All targets.
#

all: bpf loader test

clean: loader-clean bpf-clean bpftool-clean libbpf-clean
	rm -rf $(BUILDDIR)
