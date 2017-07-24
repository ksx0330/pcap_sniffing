#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "show_attr.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define IPV4 10
#define ARK 20
#define TCP 30
#define UDP 40

struct sniff_ethernet {
        u_char  ether_dhost[6];    /* destination host address */
        u_char  ether_shost[6];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	int etype=0, protocol=0;
	int size_ip, size_total;
	const struct sniff_ethernet * ethernet;
	const struct sniff_ip * ip;
	const struct sniff_tcp *tcp;

	etherent = (sniff_ethernet*)(packet);
	ip = (sniff_ip*)(packet + 14);
	size_ip = IP_HL(ip);
	tcp = (sniff_tcp*)(packet + 14 + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	size_total = ntohs(ip->len) + 14;

	printf("\ncount : %d\n", count);
	count++;

	printf("------------------------------\n");
	etype = show_addr(packet);
	if (etype == IPV4) {
		protocol = show_ipv4_ip(packet);
		
		if (protocol == TCP) {
			show_port(packet);

			if (size_total != (size_ip + size_tcp + 14)) {
				printf("------------------------------\n");

				show_data(args, header, packet, *(packet+size_total), size_total);

				printf("------------------------------\n");
			}
		} else if (protocol == UDP) {
			show_port(packet);
			printf("------------------------------\n");

			show_data(args, header, packet, 42);

			printf("------------------------------\n");
		}

		show_hex_code(args, header, packet);

		printf("------------------------------\n");
	} else if (etype == ARK) {
		show_ark_ip(packet);
		printf("------------------------------\n");

		show_hex_code(args, header, packet);

		printf("------------------------------\n");
	}
}
	

int main (int argc, char **argv) {
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char filter_exp[] = "ip";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res;

	if (argc == 2) {
		dev = argv[1];
	} else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n");
		exit(EXIT_FAILURE);
	} else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	handle = pcap_open_live (dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	while ((res = pcap_next_ex(handle, &header, &packet)) >= 0)
		if (res > 0)
			got_packet(handle, header, packet);
		else
			printf("Packet Dropped\n");

	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture Complete.\n");
	return 0;
} 
