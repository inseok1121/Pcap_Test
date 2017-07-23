#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


struct Header_ETHERNET{

    u_int8_t Destination_MacAdd[6];
    u_int8_t Source_MacAdd[6];
    u_int16_t Ether_Type;


};
struct Header_IP{
    u_int8_t verNlen;
    u_int8_t TOS;
    u_int16_t Total_Len;
    u_int16_t Identification;
    u_int16_t Fragment;
    u_int8_t TTL;
    u_int8_t Protocol;
    u_int16_t Checksum;
    struct in_addr Destination_IP, Source_IP;
};
struct Header_TCP{
    u_int16_t Source_Port;
    u_int16_t Destination_Port;
    u_int32_t Sequence;
    u_int32_t Acknow_Number;
    u_int8_t OffsetNreserved;
    u_int8_t TCPFlags;
    u_int16_t SizeofWindow;
    u_int16_t Checksum;
    u_int16_t UrgentPorinter;
};

#define SWAP(X) ((X)>>8|(X)<<8)
#define CALC_LEN(Header_TCP) ((Header_TCP->OffsetNreserved & 0xf0) >> 4)

int main(int argc, char **argv){

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    struct  pcap_pkthdr header;
    const u_char *packet;
    int res,i;
    int size_ip, size_tcp;
    u_char buf[20];
    char *data;
    const struct Header_ETHERNET *ethernet;
    const struct Header_IP *ip;
    const struct Header_TCP *tcp;

    dev = pcap_lookupdev(errbuf);
    printf("DEVICE : %s\n", dev);
    handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

    pcap_compile(handle, &fp, "PORT 80", 0, 0);
    pcap_setfilter(handle, &fp);


    while(1){
        res = pcap_next_ex(handle, &header, &packet);

        if(res == 0){
            continue;
        }else if(res == -1 || res == -2){
            printf("res = -1 or -2\n");
            break;
        }else{

            //******************************************************//
            //*****************************ETHERNET*****************//
            //******************************************************//
            ethernet = (struct Header_ETHERNET *)(packet);
	    if(!(htons(ethernet->Ether_Type) == ETHERTYPE_IP)){
                printf("This packet is not IP Packet!!\n");
                continue;
            }
            printf("[*]=========================================\n");
            printf("[*]Destination Mac Address : ");
            for(i=0; i<6; i++){
                printf("%02x", ethernet->Destination_MacAdd[i]);
                if(i < 5){
                    printf(":");
                }
            }
            printf("\n");


            printf("[*]Source Mac Address : ");
            for(i=0; i<6; i++){
                printf("%02x", ethernet->Source_MacAdd[i]);
                if(i < 5){
                    printf(":");
                }
            }
            printf("\n");

            //******************************************************//
            //*****************************IP***********************//
            //******************************************************//
            ip = (struct Header_IP *)(packet + 14);

            printf("[*]=========================================\n");
            inet_ntop(AF_INET, &ip->Destination_IP,buf, sizeof(buf));
            printf("[*]Destination IP Address : %s\n", buf);
            inet_ntop(AF_INET, &ip->Source_IP,buf, sizeof(buf));
            printf("[*]Source IP Address : %s\n", buf);
            printf("[*]IP Protocol : %02x\n", ip->Protocol);


            //******************************************************//
            //*****************************TCP**********************//
            //******************************************************//
            size_ip = (ip->verNlen & 0xf)*4;

            tcp = (struct Header_TCP*)(packet+14+size_ip);
            printf("[*]Destination TCP Port : %d\n", ntohs(tcp->Destination_Port));
            printf("[*]Source TCP Port : %d\n", ntohs(tcp->Source_Port));

            //******************************************************//
            //****************************DATA**********************//
            //******************************************************//

            size_tcp = CALC_LEN(tcp)*4;
            data = (u_char*)(packet+14+size_ip+size_tcp);
            if(ntohs(ip->Total_Len) - (size_ip + size_tcp) > 0){
                printf("[*]Data : %s\n", data);
                printf("\n\n");
            }else{
                continue;
            }


        }
    }

    return 0;
}

