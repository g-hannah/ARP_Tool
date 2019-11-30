#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define clear_struct(s) memset((s), 0, sizeof((*s)));

/*
 * On operating systems running on the Linux kernel,
 * the binary needs to either have the set UID bit
 * set (bad idea), or have its net capabilities set:
 *
 * sudo setcap cap_net_raw,cap_net_broadcast=ep </path/to/binary>
 */

int
__check_args(int argc, char *argv[])
{
	if (argc < 2)
		return 0;

	size_t arg_len = strlen(argv[1]);

	argv[1][arg_len++] = '.';
	argv[1][arg_len] = 0;

	char *s = argv[1];
	char *e = argv[1] + arg_len;
	char *dot;
	unsigned short val = 0;

/*
 * Make sure the IP address is legal. Four dots
 * in total (one appended at the end above), and
 * ensure that each isolated value is not greater
 * than 255.
 */
	while (1)
	{
		dot = memchr(s, '.', (e - s));

		if (!dot)
			goto fail;

		if ((dot - s) > 3)
			goto fail;

		val = (unsigned short)strtoul(s, &dot, 10);

		if (val > 255)
			goto fail;

		if ((dot + 1) == e)
			break;

		s = ++dot;
	}

	argv[1][--arg_len] = 0;
	return 1;

	fail:
	argv[1][--arg_len] = 0;
	fprintf(stderr, "Illegal IP address \"%s\"\n", argv[1]);
	return 0;
}

static void
__attribute__((__noreturn__)) usage(int status)
{
	fprintf(stderr,
		"iptohw <ip address>\n");

	exit(status);
}

#define HARDWARE_ADDR_SIZE 6 /* MAC addresses are 48 bits (6 bytes) */
#define PROTOCOL_SIZE 4 /* IPv4 addresses are 32 bits (4 bytes) */

/*
 * Set this to 1 when we get the name of the
 * network interface so we do not keep doing
 * it everytime __do_if_request() is called.
 */
static int got_if_name = 0;

/**
 * Do an ioctl() request
 *
 * @_ifr: the interface request structure to put result
 * @type: the type of request (e.g., SIOCGIFHWADDR)
 */
static int
__do_if_request(struct ifreq *_ifr, int type)
{
	int tmp_sock = -1;
	int i;
	struct if_nameindex *ifnames = NULL;

	tmp_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (!got_if_name)
	{
		ifnames = if_nameindex();

		if (!ifnames)
			goto fail;

		while (ifnames[i].if_name[0] != 'w')
			++i;

		if (ifnames[i].if_name[0] != 'w')
			goto fail;

		strcpy(_ifr->ifr_name, ifnames[i].if_name);
		got_if_name = 1;

#ifdef DEBUG
	fprintf(stderr, "Found wireless interface \"%s\"\n", _ifr->ifr_name);
#endif

		if_freenameindex(ifnames);
	}

	if (ioctl(tmp_sock, type, _ifr) < 0)
	{
		fprintf(stderr, "%s: failed to get device information (type=%d)\n", __func__, type);
		goto fail;
	}

	return 0;

	fail:
	return -1;
}

#define BUFFER_SIZE 512
#define ETHER_BROADCAST_ADDR { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

/*
 * Two ether addresses (12 bytes) + two inet4
 * address (8 bytes) == 20 bytes.
 */
#define ARP_DATA_SIZE 20

#define offset_of(type, name) ((size_t)&((type *)0)->name)

#if 0
struct arp_request
{
	struct ether_header eth_hdr;
	struct arphdr arp_hdr;
	struct ether_addr sender_hw;
	struct in_addr sender_ip;
	struct ether_addr dest_hw;
	struct in_addr dest_ip;
	unsigned char __padding[56];
} __attribute__((__packed__));
#endif

struct raw_sk_buf
{
	struct ether_header eth_hdr;
	struct arphdr arp_hdr;
	struct arp_data
	{
		struct ether_addr local_hw;
		struct in_addr local_ip;
		struct ether_addr remote_hw;
		struct in_addr remote_ip;
	} __attribute__((__packed__)) arp_data;
	unsigned char zero[14];

	char __mark; /* marks the end of the actual packet */

	struct sockaddr_ll sll;
	struct ifreq ifr;
	int ifidx;

} __attribute__ ((__packed__));

static const uint8_t ether_broadcast[ETH_ALEN] = ETHER_BROADCAST_ADDR;

static int
send_arp_request(const char *ip_addr)
{
	assert(ip_addr);

	struct raw_sk_buf skbuf;
	struct raw_sk_buf inbuf;
	int raw_fd = -1;

	clear_struct(&skbuf);
	clear_struct(&inbuf);

/*
 * Get the hardware address of our network interface.
 */
	if (__do_if_request(&skbuf.ifr, SIOCGIFHWADDR) < 0)
		goto fail;

	memcpy(&skbuf.arp_data.local_hw, &skbuf.ifr.ifr_hwaddr.sa_data, ETH_ALEN);

/*
 * Get the IPv4 address that our interface uses.
 */
	if (__do_if_request(&skbuf.ifr, SIOCGIFADDR) < 0)
		goto fail;

	memcpy(&skbuf.arp_data.local_ip, (void *)&((struct sockaddr_in *)&skbuf.ifr.ifr_addr)->sin_addr, PROTOCOL_SIZE);

/*
 * Get the index of the interface we want to use.
 * (we need it to fill in the link-layer socket
 * structure (struct sockaddr_ll).
 */
	if (__do_if_request(&skbuf.ifr, SIOCGIFINDEX) < 0)
		goto fail;

	skbuf.ifidx = skbuf.ifr.ifr_ifindex;

/*
 *  <---- ETHERNET ----> <---------------- ARP HEADER ---------------> <---------- ARP DATA ---------> < ETH TRAILER >
 * | DEST | SRC  | TYPE | HWTYPE | PROTO | HWSIZE | PROTSIZE | OPCODE | SRCHW | SRCIP | DSTHW | DSTIP |               |
 *   ^                                                                                  ^all zeros
 * broadcast address                                                                   in the request.
 * (ff.ff.ff.ff.ff.ff)
 */
	memcpy(&skbuf.eth_hdr.ether_dhost, ether_broadcast, ETH_ALEN);
	memcpy(&skbuf.eth_hdr.ether_shost, &skbuf.arp_data.local_hw, ETH_ALEN);
	skbuf.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	skbuf.arp_hdr.ar_hrd = htons(ARPHRD_ETHER); /* takes up two bytes */
	skbuf.arp_hdr.ar_pro = htons(ETHERTYPE_IP); /* takes up two bytes */
	skbuf.arp_hdr.ar_hln = HARDWARE_ADDR_SIZE; /* takes up one byte */
	skbuf.arp_hdr.ar_pln = PROTOCOL_SIZE; /* takes up one byte */
	skbuf.arp_hdr.ar_op = htons(ARPOP_REQUEST); /* two bytes */

	memset(&skbuf.arp_data.remote_hw, 0, ETH_ALEN);
	//memcpy(&skbuf.arp_data.remote_hw, ether_broadcast, ETH_ALEN);
/*
 * inet_addr() converts the IP in string format
 * to in_addr_t in network-byte order.
 */
	skbuf.arp_data.remote_ip.s_addr = inet_addr(ip_addr);

/*
 * We are operating below layer 3.
 */
	if ((raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
		goto fail;

	clear_struct(&skbuf.sll);

	skbuf.sll.sll_family = AF_PACKET;
	skbuf.sll.sll_protocol = htons(ETH_P_ARP);
	skbuf.sll.sll_ifindex = skbuf.ifidx;
	skbuf.sll.sll_hatype = htons(1);
	skbuf.sll.sll_pkttype = PACKET_BROADCAST;
	skbuf.sll.sll_halen = ETH_ALEN;
	memset(&skbuf.sll.sll_addr, 0, 8);
	memcpy(&skbuf.sll.sll_addr, ether_broadcast, ETH_ALEN);

	ssize_t bytes;
	size_t packet_size = offset_of(struct raw_sk_buf, __mark);

	bytes = sendto(raw_fd, &skbuf, packet_size, 0, (struct sockaddr *)&skbuf.sll, sizeof(skbuf.sll));
	if (bytes < 0)
	{
		fprintf(stderr, "%s: send error (%s)\n", __func__, strerror(errno));
		goto fail;
	}

	fprintf(stdout,
			"\n"
			"\"Who has %s? Tell %s\"\n",
			ip_addr, inet_ntoa(skbuf.arp_data.local_ip));

	//bytes = recvfrom(raw_fd, &inbuf, packet_size, 0, (struct sockaddr *)&rsll, (socklen_t *)&rlen);
	bytes = recv(raw_fd, &inbuf, packet_size, 0);

	if (bytes <= 0)
	{
		fprintf(stderr, "%s: recv error (%s)\n", __func__, strerror(errno));
		goto fail;
	}

/*
 * The hardware address will be stored within LOCAL_HW in the
 * received data buffer since it is local from the perspective
 * of the sending remote host.
 */
	fprintf(stdout,
			"\n"
			"  %s is at %s\n",
			ip_addr, ether_ntoa((const struct ether_addr *)&inbuf.arp_data.local_hw));

	return 0;

	fail:
	fprintf(stderr, "Error: %s\n", strerror(errno));
	return -1;
}

int
main(int argc, char *argv[])
{
	if (!__check_args(argc, argv))
		usage(EXIT_FAILURE);

	if (send_arp_request(argv[1]) < 0)
		goto fail;

	exit(EXIT_SUCCESS);

	fail:
	exit(EXIT_FAILURE);
}
