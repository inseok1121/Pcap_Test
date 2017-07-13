#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#define SIZE_ETHERNET 14
void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
struct ethernetheader{
	
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};
struct ipheader{
	
	u_char ip_verLength;
	u_char ip_ServiceType;
	u_short ip_Length;
	u_short ip_Identification;
	u_short ip_Fragment;

	u_char ip_Ttl;
	u_char ip_Protocol;
	u_short ip_Checksum;

	struct in_addr ip_Source, ip_Destination;

};
#define IP_HL(ip)	(((ip)->ip_verLength)&0x0f)
#define IP_V(ip)	(((ip)->ip_verLength) >> 4)
struct tcpheader{
	u_short tcp_SourcePort;
	u_short tcp_DestinationPort;
	u_int tcp_SeqNumber;
	u_int tcp_AckNumber;
	u_char tcp_Offx2;
	u_char tcp_Flags;
	u_short tcp_SizeWindow;
	u_short tcp_Checksum;
	u_short tcp_UrgentPointer;

};
#define TH_OFF(tcp)  (((tcp)->tcp_Offx2 & 0xf0) >> 4)
#define  SWAP(s)   (((((s) & 0xff) << 8) | (((s) >> 8) & 0xff)))  
int main(){

	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	char *net;
	char *mask;
	int check;
	bpf_u_int32 netp; //ip
	bpf_u_int32 maskp; // subnet mask
	struct in_addr addr;
	
	pcap_t *packet;
	const u_char *pk;
	struct bpf_program fcode;

	dev = pcap_lookupdev(errbuf);
	check = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	printf("Device : %s\n", dev);

	if(check == -1){
		printf("%s\n", errbuf);
		return 0;
	}

	addr.s_addr = netp;
	net = inet_ntoa(addr);

	printf("Net : %s\n", net);

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);

	printf("Mask : %s\n", mask);

	
	//pcatp_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms. char *ebuf)
	// snaplen : Maximum Packet's size 
	// promisc : Select Mode(Promiscuous mode = 1(Capture All Packet)
	//			(Promiscuous mode = 0(Capture the Packet that send to me)
	// to_ms   : For set time out(unit : millisecond)
	

	//pcap_t *pcap_open_offine(char *fname, char *ebuf)
	//fname    : Read packets from the file that have fname. If fname is "-", Read from stdin		
	
	//pcap_t* pcap_setfilter(pcap_t* packet, &fcode)

	printf("===========================\n");
	packet = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
	printf("live\n");
	if(packet == NULL){
		printf("%s\n", errbuf);
		return 0;
	}


	
	check = pcap_compile(packet, &fcode, "port 80", 0, mask);
	printf("compile\n");
	if(check  < 0){
		perror(pcap_geterr(packet));
		return 0;
	}
	
	check = pcap_setfilter(packet, &fcode);
	printf("setfilter\n");
	if(check< 0){
		perror(pcap_geterr(packet));
		return 0;
	}

	check = pcap_loop(packet, 10, packet_view, 0);
	printf("loop\n");
	if(check < 0){
		perror(pcap_geterr(packet));
		return 0;
	}

 

	return 0;
}
void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet){
	
	int i;	

	int len = h->len;
		
	const struct ethernetheader *ethernet;
	const struct ipheader *ip;
	const struct tcpheader *tcp;
	const char *data;

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct ethernetheader*)(packet);
	printf("[*]=========================================\n");
	printf("[*]Destination Mac Address : ");
	for(i=0; i<6; i++){
		printf("%02x", ethernet->ether_dhost[i]);
		if(i < 5){
			printf(":");
		}
	}
	printf("\n");


        printf("[*]Source Mac Address : ");
        for(i=0; i<6; i++){
                printf("%02x", ethernet->ether_shost[i]);
                if(i < 5){
                        printf(":");
                }
        }
        printf("\n");
	ip = (struct ipheader*)(packet + SIZE_ETHERNET);
	printf("[*]=========================================\n");	
	printf("[*]Destination IP Address : %s\n", inet_ntoa(ip->ip_Destination));
	printf("[*]Source IP Address : %s\n", inet_ntoa(ip->ip_Source));	
	printf("[*]IP Protocol : %02x\n", ip->ip_Protocol);

	size_ip = IP_HL(ip)*4;
	printf("[*]=========================================\n");
	
	tcp = (struct tcpheader*)(packet+SIZE_ETHERNET+size_ip);
	printf("[*]Destination TCP Port : %d\n", SWAP(tcp->tcp_DestinationPort));
	printf("[*]Source TCP Port : %d\n", SWAP(tcp->tcp_SourcePort));
	
	size_tcp = TH_OFF(tcp)*4;
	
	data = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	printf("[*]Data : %s\n", data);	
	printf("\n\n");
	return;

}
