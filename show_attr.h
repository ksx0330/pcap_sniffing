#ifndef __show_attr_h__
#define __show_attr_h__
void show_port (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void show_ark_ip (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int show_ipv4_ip (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int show_addr (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void show_hex_code(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void show_data (u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int head_size);
#endif

