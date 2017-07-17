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

void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	int etype, protocol;

	printf("\ncount : %d\n", count);
	count++;

	printf("------------------------------\n");
	etype = show_addr(args, header, packet);
	if (etype == IPV4) {
		protocol = show_ipv4_ip(args, header, packet);
		
		if (protocol == TCP) {
			show_port(args, header, packet);
			printf("------------------------------\n");

			show_data(args, header, packet, 54);

			printf("------------------------------\n");
		} else if (protocol == UDP) {
			show_port(args, header, packet);
			printf("------------------------------\n");

			show_data(args, header, packet, 42);

			printf("------------------------------\n");
		}

		show_hex_code(args, header, packet);

		printf("------------------------------\n");
	} else if (etype == ARK) {
		show_ark_ip(args, header, packet);
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

	while (pcap_next_ex(handle, &header, &packet) >= 0)
		got_packet(handle, header, packet);

	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture Complete.\n");
	return 0;
} 
