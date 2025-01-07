LINUX=$(HOME)/src/linux
VMLINUX=$(LINUX)/vmlinux
# TODO: use system libbpf
LIBBPF=$(LINUX)/tools/lib
TOOLS=$(LINUX)/tools/testing/selftests/net/tools/include

all: xskrtt

vmlinux.h:
	bpftool btf dump file $(VMLINUX) format c > $@

xskrtt.bpf.o: xskrtt.bpf.c vmlinux.h
	clang -g -O2 $(CFLAGS) -I$(PWD) -I$(TOOLS) -I$(LIBBPF) --target=bpf -mcpu=v4 -c $< -o $@

xskrtt.skel.h: xskrtt.bpf.o
	bpftool gen skeleton $< name xskrtt > $@

xskrtt: xskrtt.c xskrtt.skel.h
	clang -O2 -static -L$(LIBBPF)/bpf -I$(TOOLS) $< -lbpf -lelf -lz -lzstd -o $@

clean:
	rm -f xskrtt.bpf.o xskrtt.skel.h xskrtt
