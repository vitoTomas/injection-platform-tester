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
	ln -s $(BPFTOOL_BIN) bpftool.ln
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
BPF_SRC := src/probe
BPF_OBJ := $(shell pwd)/$(BUILDDIR)/bpf.o

bpf: libbpf bpftool
	mkdir -p $(BUILDDIR)
	make BUILD=y INCLUDE_BPF=$(LIBBPF_INCLUDE) \
	INCLUDE_LINUX=$(BPFTOOL_INCLUDE) OBJ=$(BPF_OBJ) -C src/probe build;
	bpftool gen skeleton $(BPF_OBJ) > \
	$(BUILDDIR)/$(notdir $(basename $(BPF_OBJ))).h

bpf-clean:
	make OBJ=$(BPF_OBJ) -C src/probe clean;

#
# All targets.
# 

clean: bpf-clean bpftool-clean libbpf-clean
	rm -rf $(BUILDDIR)
