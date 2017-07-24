#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "show_attr.h"

#define IPV4 10
#define ARP 20
#define TCP 30
#define UDP 40

struct sniff_ethernet {
        u_char  ether_dhost[16];    /* destination host address */
        u_char  ether_shost[16];    /* source host address */
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

struct sniff_arp {
	u_short arp_htype; /*hardware type*/
	u_short arp_p; /*protocol*/
	u_char arp_hsize; /*hardware size*/
	u_char arp_psize; /*protocol size*/
	u_short arp_opcode; /*opcode*/
	u_char arp_smhost[16]; /*sender mac address*/
	struct in_addr arp_sip; /*sender ip address*/
	u_char arp_dmhost[16]; /*target mac address*/
	struct in_addr arp_dip; /*target ip address*/
};
	
typedef u_int tcp_seq;

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

const struct sniff_ethernet * ethernet;
const struct sniff_ip * ip;
const struct sniff_arp * arp;
const struct sniff_tcp * tcp;

int show_addr (const u_char *packet) {
	int i;
	int temp = 0;

	ethernet = (struct sniff_ethernet*)(packet);

	if ((((*(packet+12)) & 0xff)*0x100 + ((*(packet+13)) & 0xff)) == 0x800) {
		printf("Ether_type = IPv4\n");
		printf("Src_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", ethernet->ether_shost[i]);
			else
				printf("%.2x\n", ethernet->ether_shost[i]);
		}

		printf("Dest_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", ethernet->ether_dhost[i]);
			else
				printf("%.2x\n", ethernet->ether_dhost[i]);
		}

		return IPV4;
	} else if ((((*(packet+12)) & 0xff)*0x100 + ((*(packet+13)) & 0xff)) == 0x806) {
		printf("Ether_type = ARP\n");
		printf("Src_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", ethernet->ether_shost[i]);
			else
				printf("%.2x\n", ethernet->ether_shost[i]);
		}

		printf("Dest_address : ");
		for (i=0; i<6; i++) {
			if (i < 5)
				printf("%.2x : ", ethernet->ether_dhost[i]);
			else
				printf("%.2x\n", ethernet->ether_dhost[i]);
		}

		return ARP;
	}
	printf("\n");
	return 0;
}

int show_ipv4_ip (const u_char *packet) {
	int i;
	char src_ip[100], dst_ip[100];
	ip = (struct sniff_ip*)(packet + 14);
	
	inet_ntop(AF_INET, &(ip->ip_src), src_ip, 100);
	inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, 100);

	printf("Src_ip : %s\n", src_ip);

	printf("Dest_ip : %s\n", dst_ip);

	if (ip->ip_p == 0x6) {
		printf("Protocol : TCP\n");
		return TCP;
	} else if (ip->ip_p == 0x11) {
		printf("Protocol : UDP\n");
		return UDP;
	}

	printf("\n");
	return 0;
}

void show_ark_ip (const u_char *packet) {
	int i;
	char src_ip[100], dst_ip[100];
	arp = (struct sniff_arp*)(packet + 14);

	inet_ntop(AF_INET, &(arp->arp_sip), src_ip, 100);
	inet_ntop(AF_INET, &(arp->arp_dip), dst_ip, 100);

	printf("Src_ip : %s\n", src_ip);

	printf("Dest_ip : %s\n", dst_ip);

	printf("\n");
}

void show_port (const u_char *packet) {
	int size_ip;

	ip = (struct sniff_ip*)(packet + 14);
	size_ip = IP_HL(ip);
	tcp = (struct sniff_tcp*)(packet + size_ip + 14);

	printf("Src_port : %d\n", ntohs(tcp->th_sport));

	printf("Dest_port : %d\n", ntohs(tcp->th_dport));
}

void show_data (u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int head_size, int size_total) {
	int i, tmp;

	printf("Data Code : \n ");
	for (i=head_size; i<size_total; i++) {
		printf("%.2x ", *(packet+i)&0xff);
		tmp++;

		if (tmp%16 == 15)
			printf("\n");
		if (tmp%8 == 7)
			printf(" ");
	}

	printf("\n");
}
