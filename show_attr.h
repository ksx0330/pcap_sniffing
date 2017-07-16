#ifndef __show_attr_h__
#define __show_attr_h__
void show_port (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void show_ip (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void show_addr (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void show_hex_code(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
#endif

