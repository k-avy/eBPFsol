# Filename: bpf/Makefile

CLANG := clang
CFLAGS := -O2 -target bpf

all: drop_tcp_port.o

drop_tcp_port.o: drop_tcp_port.c
	$(CLANG) $(CFLAGS) -c drop_tcp_port.c -o drop_tcp_port.o

clean:
	rm -f *.o
