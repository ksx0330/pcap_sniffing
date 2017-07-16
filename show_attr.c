#include <pcap.h>
#include "show_attr.h"

void show_port (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int dest_port;
	int src_port;

	src_port = ((*(packet+34)) & 0xff)*0x100 + ((*(packet+35)) & 0xff);
	dest_port = ((*(packet+36)) & 0xff)*0x100 + ((*(packet+37)) & 0xff);

	printf("src_port : %d\n", src_port);

	printf("dest_port : %d\n", dest_port);
}

void show_ip (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int dest_ip[4] = {0};
	int src_ip[4] = {0};

	int i;

	for (i=0; i<4; i++) {
		dest_ip[i] = ((*(packet+i+26)) & 0xff);
		src_ip[i] = ((*(packet+i+26+4)) & 0xff);
	}

	printf("src_ip : ");
	for (i=0; i<4; i++) {
		if (i < 3)
			printf("%d : ", dest_ip[i]);
		else
			printf("%d\n", dest_ip[i]);
	}

	printf("dest_ip : ");
	for (i=0; i<4; i++) {
		if (i < 3)
			printf("%d : ", src_ip[i]);
		else
			printf("%d\n", src_ip[i]);
	}

	printf("\n");
}

void show_addr (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int dest_addr[6] = {0};
	int src_addr[6] = {0};

	int i;
	int temp = 0;

	for (i=0; i<6; i++) {
		dest_addr[i] = ((*(packet+i)) & 0xff);
		src_addr[i] = ((*(packet+i+6)) & 0xff);
	}

	printf("src_address : ");
	for (i=0; i<6; i++) {
		if (i < 5)
			printf("%.2x : ", src_addr[i]);
		else
			printf("%.2x\n", src_addr[i]);
	}

	printf("dest_address : ");
	for (i=0; i<6; i++) {
		if (i < 5)
			printf("%.2x : ", dest_addr[i]);
		else
			printf("%.2x\n", dest_addr[i]);
	}

	printf("\n");
}

void show_hex_code(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int i;

	printf(" ");
	for (i=0; i<(*header).len; i++) {
		printf("%.2x ", *(packet+i)&0xff);

		if (i%16 == 15)
			printf("\n");
		if (i%8 == 7)
			printf(" ");
	}

	printf("\n");
}
