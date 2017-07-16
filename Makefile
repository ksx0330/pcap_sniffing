all: pcap_sniffing

pcap_sniffing: pcap.o show_attr.o
	gcc -w -o pcap_sniffing pcap.o show_attr.o -l pcap

show_attr.o: show_attr.c show_attr.h
	gcc -w -c -o show_attr.o show_attr.c -l pcap

pcap.o: pcap.c show_attr.h
	gcc -w -c -o pcap.o pcap.c

clean: 
	rm *.o pcap_sniffing
