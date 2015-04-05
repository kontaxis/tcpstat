/* kontaxis 2014-11-03 */

#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <pcap/pcap.h>

#include <stdlib.h>
#include <signal.h>

#if __WITH_THREADS__
#include <pthread.h>
#endif

#if !__DEBUG__
#define NDEBUG
#endif
#include <assert.h>

/* References:
 *   netinet/ether.h
 *   netinet/ip.h
 *   netinet/tcp.h
 *   netinet/udp.h
 */

/* Ethernet */

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

#define ETHERTYPE_IP 0x0800 /* IP */

#if !__NO_ETHERNET__
#define SIZE_ETHERNET sizeof(struct ether_header)
#else
#define SIZE_ETHERNET 0
#endif

/* IP */

struct my_iphdr
{
  uint8_t  vhl;
#define IP_HL(ip) (((ip)->vhl) & 0x0F)
#define IP_V(ip)  (((ip)->vhl) >> 4)
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /*The options start here. */
} __attribute__ ((__packed__));

#define MIN_SIZE_IP (sizeof(struct my_iphdr))
#define MAX_SIZE_IP (0xF * sizeof(uint32_t))

#define IPVERSION 4

#define IPPROTO_TCP  6
#define IPPROTO_UDP 17

/* TCP */

struct my_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  res1doff;
#define TCP_OFF(th)      (((th)->res1doff & 0xF0) >> 4)
	uint8_t  flags;
#define TCP_FIN  (0x1 << 0)
#define TCP_SYN  (0x1 << 1)
#define TCP_RST  (0x1 << 2)
#define TCP_PUSH (0x1 << 3)
#define TCP_ACK  (0x1 << 4)
#define TCP_URG  (0x1 << 5)
#define TCP_ECE  (0x1 << 6)
#define TCP_CWR  (0x1 << 7)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__ ((__packed__));

#define MIN_SIZE_TCP (sizeof(struct my_tcphdr))
#define MAX_SIZE_TCP (0xF * sizeof(uint32_t))

/* UDP */

struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} __attribute__ ((__packed__));

#define MIN_SIZE_UDP (sizeof(struct udphdr))


/* converts 16 bits in host byte order to 16 bits in network byte order */
#if !__BIG_ENDIAN__
#define h16ton16(n) \
((uint16_t) (((uint16_t) n) << 8) | (uint16_t) (((uint16_t) n) >> 8))
#else
#define h16ton16(n) (n)
#endif

#define n16toh16(n) h16ton16(n)

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)


#if __WITH_THREADS__
pthread_t my_thread;
void *my_thread_retval;
#endif

pcap_t *pcap_handle;
#if __DEBUG__
pcap_dumper_t * pcap_dumper_handle;
#endif


/* Packet count per destination port.
 * -  TCP: with the proper BPF (see default) this could count flots.
 * -  UDP: no conntrack support so we just count packets.
 * - ICMP: no notion of ports so flow_counts[0] counts all packets.
 *
 * Stored in network byte-order to save some shifts on little-endians.
 */
uint32_t flow_counts[0xFFFF + 1];

void my_pcap_handler (uint8_t *user, const struct pcap_pkthdr *header,
	const uint8_t *packet)
{
#if !__NO_ETHERNET__
	struct ether_header *ether;
#endif
	struct my_iphdr *ip;
	struct my_tcphdr *tcp;
	struct udphdr *udp;

#if __DEBUG__
	uint16_t src_port;
#endif
	uint16_t dst_port;

#if !__NO_ETHERNET__
	/* Process ethernet header */
	assert(header->caplen >= SIZE_ETHERNET);
	ether = (struct ether_header *) packet;
	if (unlikely(ether->ether_type != h16ton16(ETHERTYPE_IP))) {
#if __DEBUG__
		fprintf(stderr,
			"WARNING: ether->ether_type != ETHERTYPE_IP. Ignoring.\n");
#endif
		return;
	}
#endif

	/* Process IP header */
	assert(header->caplen >= SIZE_ETHERNET + MIN_SIZE_IP);
	ip = (struct my_iphdr *) (packet + SIZE_ETHERNET);
	if (unlikely(IP_V(ip) != IPVERSION)) {
#if __DEBUG__
		fprintf(stderr, "WARNING: IP_V(ip) != 4. Ignoring.\n");
#endif
		return;
	}

	switch(ip->protocol) {
		case IPPROTO_TCP: {
				/* Process TCP header */
				assert(header->caplen >=
					SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) + MIN_SIZE_TCP);
				tcp = (struct my_tcphdr *)
					(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)));
#if __DEBUG__
				src_port = tcp->source;
#endif
				dst_port = tcp->dest;
			}
			break;
		case IPPROTO_UDP: {
				/* Process UDP header */
				assert(header->caplen >=
					SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) + MIN_SIZE_UDP);
				udp = (struct udphdr *)
					(packet + SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)));
#if __DEBUG__
				src_port = udp->source;
#endif
				dst_port = udp->dest;
			}
			break;
		default:
#if __DEBUG__
				src_port = 0;
#endif
				dst_port = 0;
			break;
	}

#if __DEBUG__
	/* Save to dump file. We do this after we transmit to the dispatcher so
	 * that the dump reflects only packets that were sucessfuly transmitted. */
	pcap_dump((u_char *)pcap_dumper_handle, header, packet);
#endif

#if __DEBUG__
	fprintf(stdout, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:[%u]\n",
		*(((uint8_t *)&(ip->saddr)) + 0),
		*(((uint8_t *)&(ip->saddr)) + 1),
		*(((uint8_t *)&(ip->saddr)) + 2),
		*(((uint8_t *)&(ip->saddr)) + 3),
		n16toh16(src_port),
		*(((uint8_t *)&(ip->daddr)) + 0),
		*(((uint8_t *)&(ip->daddr)) + 1),
		*(((uint8_t *)&(ip->daddr)) + 2),
		*(((uint8_t *)&(ip->daddr)) + 3),
		n16toh16(dst_port));
#endif

	/* If one counter is about to overflow, reset them all */
	if (unlikely(flow_counts[dst_port] == UINT_MAX)) {
		memset(flow_counts, 0, sizeof(flow_counts));
	}

	/* Increase flow count for this destination port */
	flow_counts[dst_port] += 1;
}


void print_flow_counts(void)
{
	uint32_t i;
	uint16_t j;

	for (i = 0, j = 0; i <= 0xFFFF; i++) {
		if (!flow_counts[h16ton16(i)]) continue;
		fprintf(stdout, "%u:%u ", i, flow_counts[h16ton16(i)]);
		j++;
	}
	fprintf(stdout, "\n");
	fprintf(stdout, "[*] Ports identified: %u\n", j);
}


void print_flow_counts_pretty(void)
{
	uint32_t i;
	uint16_t j;

	fprintf(stdout, "=== BEGIN DATA ===\n");

	for (i = 0, j = 0; i <= 0xFFFF; i++) {
		if (!flow_counts[h16ton16(i)]) continue;
		fprintf(stdout, "[\033[1;32m%5u\033[0m] = \033[1;31m%10u\033[0m",
			i, flow_counts[h16ton16(i)]);

		if (!((j + 1) % 3)) {fprintf(stdout, "\n");}
		else {fprintf(stdout, " ");}
		j++;
	}

	if (j == 0) {fprintf(stdout, "NO_DATA\n");}
	else if ((j % 3)) {	fprintf(stdout, "\n");}

	fprintf(stdout, "=== END   DATA ===\n");
}


#if __WITH_THREADS__
void * status_thread (void * data)
{
	int c;
	while ((c = getchar())) {
		print_flow_counts_pretty();
	}

	assert(0);
	return NULL;
}
#endif


void signal_handler (int signum)
{
	switch(signum) {
		case SIGTERM:
		case SIGINT:
			fprintf(stdout, "\n");
			print_flow_counts();
			pcap_breakloop(pcap_handle);
			break;
		case SIGUSR1:
			print_flow_counts_pretty();
			break;
		default:
			break;
	}
}

#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define SNAPLEN_TCP (SIZE_ETHERNET + MAX_SIZE_IP + MIN_SIZE_TCP)
#define SNAPLEN_UDP (SIZE_ETHERNET + MAX_SIZE_IP + MIN_SIZE_UDP)
#define SNAPLEN MAX(SNAPLEN_TCP, SNAPLEN_UDP)
#define PROMISCUOUS ((opt_flags & OPT_PROMISCUOUS) == OPT_PROMISCUOUS)
#define PCAP_TIMEOUT 1000

#define BPF_DEFAULT \
	"ip and tcp and (tcp[tcpflags] == tcp-syn) and (dst port 80 or dst port 443)"
#define BPF bpf_s
#define BPF_OPTIMIZE 1

int main (int argc, char *argv[])
{
	char * device;
	char errbuf[PCAP_ERRBUF_SIZE];

	char * bpf_s;
	char * bpf_default = BPF_DEFAULT;
	struct bpf_program bpf;

#if __DEBUG__
	char *       dump_fname;
	unsigned int dump_fname_sz;
#endif

	struct sigaction act;

	int i;
#define OPT_DEVICE      (0x1 << 0)
#define OPT_PROMISCUOUS (0x1 << 1)
#define OPT_BPF         (0x1 << 2)
	uint8_t opt_flags;

	opt_flags = 0;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	while ((i = getopt(argc, argv, "hvf:pi:")) != -1) {
		switch(i) {
			case 'h':
				fprintf(stderr,
					"Use: %s [-h] [-v] [-f bpf] [-p] -i interface\n", argv[0]);
				return -1;
				break;
			case 'v':
				fprintf(stderr, "Build:\t%s\t%s\n", __DATE__, __TIME__);
				return -1;
				break;
			case 'f':
				bpf_s = optarg;
				opt_flags |= OPT_BPF;
				break;
			case 'p':
				opt_flags |= OPT_PROMISCUOUS;
				break;
			case 'i':
				device = optarg;
				opt_flags |= OPT_DEVICE;
				break;
			default:
				break;
		}
	}

	if (!(opt_flags & OPT_DEVICE)) {
		fprintf(stderr, "[FATAL] Missing target interface. Try with -h.\n");
		return -1;
	}

#if __DEBUG__
#if !__BIG_ENDIAN__
	fprintf(stderr, "LITTLE_ENDIAN\n");
#else
	fprintf(stderr, "BIG_ENDIAN\n");
#endif
#endif

	fprintf(stdout, "[*] PID: %u\n", getpid());

	fprintf(stdout, "[*] Device: '%s'\n", device);

	/* BPF is not set. We'll use the default. */
	if (!(opt_flags & OPT_BPF)) {
		bpf_s = bpf_default;
		opt_flags |= OPT_BPF;
	}

	fprintf(stdout, "[*] Promiscuous: %s%d\033[0m\n",
		(PROMISCUOUS?"\033[1;32m":"\033[1;31m"), PROMISCUOUS);

	if (!(pcap_handle =
		pcap_open_live(device, SNAPLEN, PROMISCUOUS, PCAP_TIMEOUT, errbuf))) {
		fprintf(stderr, "[FATAL] %s\n", errbuf);
		return -1;
	}

	if (opt_flags & OPT_BPF) {
		fprintf(stdout, "[*] BPF: '\033[1;32m%s\033[0m'\n", bpf_s);
	} else {
		fprintf(stdout, "[*] BPF: \033[1;31mNONE\033[0m\n");
	}

	if (opt_flags & OPT_BPF) {
		if (pcap_compile(pcap_handle, &bpf, BPF, BPF_OPTIMIZE,
			PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "[FATAL] Couldn't parse filter. %s\n",
				pcap_geterr(pcap_handle));
			pcap_close(pcap_handle);
			return -1;
		}

		if (pcap_setfilter(pcap_handle, &bpf) == -1) {
			fprintf(stderr, "[FATAL] Couldn't install filter. %s\n",
			pcap_geterr(pcap_handle));
			pcap_close(pcap_handle);
			return -1;
		}

		pcap_freecode(&bpf);
	}

	act.sa_handler = signal_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGINT.\n");
	}

	if (sigaction(SIGTERM, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGTERM.\n");
	}

	if (sigaction(SIGUSR1, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGUSR1.\n");
	}

#if __WITH_THREADS__
	if (pthread_create(&my_thread, NULL, &status_thread, NULL)) {
		fprintf(stderr, "[WARNING] Failed to create thread.\n");
	}
#endif

#if __DEBUG__
	dump_fname_sz = strlen(device) + strlen(".pcap") + 1;
	if ((dump_fname = malloc(sizeof(char) * dump_fname_sz)) == NULL) {
		perror("malloc");
		return -1;
	}
	snprintf(dump_fname, dump_fname_sz, "%s%s", device, ".pcap");
	if (!(pcap_dumper_handle = pcap_dump_open(pcap_handle, dump_fname))) {
		pcap_geterr(pcap_handle);
	}
	free(dump_fname);
#endif

	fprintf(stdout, "Capturing ...\n");

	if (pcap_loop(pcap_handle, -1, &my_pcap_handler, NULL) == -1) {
		fprintf(stderr, "[FATAL] pcap_loop failed. %s\n",
			pcap_geterr(pcap_handle));
	}

	pcap_close(pcap_handle);

#if __DEBUG__
	pcap_dump_close(pcap_dumper_handle);
#endif

#if __WITH_THREADS__
	if (pthread_cancel(my_thread)) {
		fprintf(stderr, "[WARNING] Failed to cancel thread.\n");
	}
	if (pthread_join(my_thread, &my_thread_retval)) {
		fprintf(stderr, "[WARNING] Failed to join thread.\n");
	}
	if (my_thread_retval != PTHREAD_CANCELED) {
		fprintf(stderr, "[WARNING] Thread hasn't been canceled.\n");
	}
#endif

	fprintf(stdout, "Goodbye\n");

	return 0;
}
