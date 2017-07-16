#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	show_addr(args, header, packet);
	show_hex_code(args, header, packet);
}

void show_addr (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int dest_addr[6] = {0};
	int src_addr[6] = {0};

	int addr = 6;
	int ip = 0;

	int i;
	int temp = 0;

	for (i=0; i<6; i++) {
		dest_addr[i] = ((*(packet+i)) & 0xff);
		src_addr[i] = ((*(packet+i+6)) & 0xff);
	}

	printf("dest_address : ");
	for (i=0; i<6; i++) {
		if (i < 5)
			printf("%.2x : ", dest_addr[i]);
		else
			printf("%.2x\n", dest_addr[i]);
	}

	printf("src_address : ");
	for (i=0; i<6; i++) {
		if (i < 5)
			printf("%.2x : ", src_addr[i]);
		else
			printf("%.2x\n", src_addr[i]);
	}

	printf("\n");
}

void show_hex_code(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	int i;

	printf("\ncount : %d\n ", count);
	for (i=0; i<(*header).len; i++) {
		printf("%.2x ", *(packet+i)&0xff);

		if (i%16 == 15)
			printf("\n");
		if (i%8 == 7)
			printf(" ");
	}

	printf("\n\n");
	count++;
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
