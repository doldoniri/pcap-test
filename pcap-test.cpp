#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test enp0s3\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */ //6bytes
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */ //6bytes
    u_int16_t ether_type;                 /* protocol */ // 2bytes
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t  th_flags;       /* control flags */

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

int tcp_check(const u_char* packet){
	struct libnet_ipv4_hdr* p;
	packet = packet + sizeof(struct libnet_ethernet_hdr);
	p = (struct libnet_ipv4_hdr*)packet;
	
	if((*p).ip_p = 6) return 1;
	else printf("NO TCP packet\n"); return 0;
}

void eth_header(const u_char* packet){
	struct libnet_ethernet_hdr* p1;
	p1 = (struct libnet_ethernet_hdr*)packet;

	printf("1-1. Ethernet Header's src mac : ");

	for(int i=0; i<5; i++){
		printf("%02x:", (*p1).ether_shost[i]);
	}
	printf("%02x\n", (*p1).ether_shost[5]);
			
	printf("1-2. Ethernet Header's dst mac : ");

        for(int i=0; i<5; i++){
                printf("%02x:", (*p1).ether_dhost[i]);
        }
        printf("%02x\n", (*p1).ether_dhost[5]);

	printf("\n");
}

void ip_header(const u_char* packet){
	struct libnet_ipv4_hdr* p2;
	packet = packet + sizeof(struct libnet_ethernet_hdr);
	p2 = (struct libnet_ipv4_hdr*)packet;
	
	printf("2-1. IP Header's src ip : %s\n", inet_ntoa((*p2).ip_src)); // IPv4 addr --> string addr
	printf("2-2. IP Header's dst ip : %s\n", inet_ntoa((*p2).ip_dst));

	printf("\n");
}

void tcp_header(const u_char* packet){
	struct libnet_tcp_hdr* p3;
	packet = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr);
	p3 = (struct libnet_tcp_hdr*)packet;

	printf("3-1. TCP Header's src port : %d\n", ntohs((*p3).th_sport));
	printf("3-2. TCP Hedaer's dst port : %d\n", ntohs((*p3).th_dport));

	printf("\n");
}

void payload(const u_char* packet){
	packet = packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
	
	printf("4. Payload(Data)'s hexadecimal value : ");
	for(int i=0; i<7; i++){
		printf("%02x ", *(packet+i));
	}

	printf("%02x\n", *(packet+7));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1; // init

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		
		tcp_check(packet);
		if(tcp_check(packet)){
			eth_header(packet);
			ip_header(packet);
			tcp_header(packet);
			payload(packet);			
		}


		printf("---\n");

	}	
	
	pcap_close(pcap);
}
