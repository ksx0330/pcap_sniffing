#include <pcap.h>
#include "show_attr.h"

#define IPV4 10
#define ARK 20
#define TCP 30
#define UDP 40


int show_addr (const u_char *packet) {
	int dest_addr[6] = {0};
	int src_addr[6] = {0};
	int ether_type;

	int i;
	int temp = 0;

	for (i=0; i<6; i++) {
		dest_addr[i] = ((*(packet+i)) & 0xff);
		src_addr[i] = ((*(packet+i+6)) & 0xff);
	}

	if ((((*(packet+12)) & 0xff)*0x100 + ((*(packet+13)) & 0xff)) == 0x800) {
		printf("Ether_type = IPv4\n");
		printf("Src_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", src_addr[i]);
			else
				printf("%.2x\n", src_addr[i]);
		}

		printf("Dest_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", dest_addr[i]);
			else
				printf("%.2x\n", dest_addr[i]);
		}

		return IPV4;
	} else if ((((*(packet+12)) & 0xff)*0x100 + ((*(packet+13)) & 0xff)) == 0x806) {
		printf("Ether_type = ARK\n");
		printf("Src_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", src_addr[i]);
			else
				printf("%.2x\n", src_addr[i]);
		}

		printf("Dest_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", dest_addr[i]);
			else
				printf("%.2x\n", dest_addr[i]);
		}

		return ARK;
	}
	printf("\n");
}

int show_ipv4_ip (const u_char *packet) {
	int dest_ip[4] = {0};
	int src_ip[4] = {0};
	int protocol = ((*(packet+23)) & 0xff);

	int i;

	for (i=0; i<4; i++) {
		src_ip[i] = ((*(packet+i+26)) & 0xff);
		dest_ip[i] = ((*(packet+i+26+4)) & 0xff);
	}

	printf("Src_ip : ");
	for (i=0; i<4; i++) {
		if (i < 3)
			printf("%d.", src_ip[i]);
		else
			printf("%d\n", src_ip[i]);
	}

	printf("Dest_ip : ");
	for (i=0; i<4; i++) {
		if (i < 3)
			printf("%d.", dest_ip[i]);
		else
			printf("%d\n", dest_ip[i]);
	}

	if (protocol == 0x6) {
		printf("Protocol : TCP\n");
		return TCP;
	} else if (protocol == 0x11) {
		printf("Protocol : UDP\n");
		return UDP;
	}

	printf("\n");
}

void show_ark_ip (const u_char *packet) {
	int sender_ip[4] = {0};
	int target_ip[4] = {0};

	int i;

	for (i=0; i<4; i++) {
		sender_ip[i] = ((*(packet+i+28)) & 0xff);
		target_ip[i] = ((*(packet+i+38)) & 0xff);
	}

	printf("Src_ip : ");
	for (i=0; i<4; i++) {
		if (i < 3)
			printf("%d.", sender_ip[i]);
		else
			printf("%d\n", sender_ip[i]);
	}

	printf("Dest_ip : ");
	for (i=0; i<4; i++) {
		if (i < 3)
			printf("%d.", target_ip[i]);
		else
			printf("%d\n", target_ip[i]);
	}

	printf("\n");
}

void show_port (const u_char *packet) {
	int dest_port;
	int src_port;

	src_port = ((*(packet+34)) & 0xff)*0x100 + ((*(packet+35)) & 0xff);
	dest_port = ((*(packet+36)) & 0xff)*0x100 + ((*(packet+37)) & 0xff);

	printf("Src_port : %d\n", src_port);

	printf("Dest_port : %d\n", dest_port);
}

void show_data (u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int head_size) {
	int i, tmp;

	printf("Data Code : \n ");
	for (i=head_size; i<(*header).len; i++) {
		printf("%.2x ", *(packet+i)&0xff);
		tmp++;

		if (tmp%16 == 15)
			printf("\n");
		if (tmp%8 == 7)
			printf(" ");
	}

	printf("\n");
}

void show_hex_code(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int i;

	printf("Hex Code : \n ");
	for (i=0; i<(*header).len; i++) {
		printf("%.2x ", *(packet+i)&0xff);

		if (i%16 == 15)
			printf("\n");
		if (i%8 == 7)
			printf(" ");
	}

	printf("\n");
}
