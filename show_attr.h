#ifndef __show_attr_h__
#define __show_attr_h__
void show_port (const u_char *packet);
void show_ark_ip (const u_char *packet);
int show_ipv4_ip (const u_char *packet);
int show_addr (const u_char *packet);
void show_data (u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int head_size, int size_total);
#endif

