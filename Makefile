.PHONY: all clean

all: tcpstat tcpstat_noether

debug: tcpstat_dbg tcpstat_noether_dbg

tcpstat: tcpstat.c
	gcc -Wall \
		tcpstat.c \
		-lpcap \
		-o tcpstat

tcpstat_dbg: tcpstat.c
	gcc -Wall -ggdb -O0 -D__DEBUG__ \
		tcpstat.c \
		-lpcap \
		-o tcpstat_dbg

tcpstat_noether: tcpstat.c
	gcc -Wall \
		-D__NO_ETHERNET__ \
		tcpstat.c \
		-lpcap \
		-o tcpstat_noether

tcpstat_noether_dbg: tcpstat.c
	gcc -Wall -ggdb -O0 -D__DEBUG__ \
		-D__NO_ETHERNET__ \
		tcpstat.c \
		-lpcap \
		-o tcpstat_noether_dbg


clean:
	rm -f tcpstat tcpstat_dbg tcpstat_noether tcpstat_noether_dbg


