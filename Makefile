all: pcap_test

pcap_test : pcap_test.c
	gcc -o pcap_test pcap_test.c -lpcap -I/usr/include/pcap

clean:
	rm -f pcap_test
	
