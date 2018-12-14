#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/netdevice.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10

const char *get_str = "GET";
const char *fake = "blocked";

struct rst_packet {
	struct ether_header eth_header;
	struct ip ip4_header;
	struct tcphdr tcp_header;
};

void usage() {
	printf("syntax: tcp_block <interface>\n");
	printf("sample: tcp_block ens33\n");
}

void IP_checksum(ip *ip_hd) {
	u_int16_t *p = (u_int16_t*)ip_hd;
	int len = 20;
	u_int32_t checksum = 0;
	len >>= 1;
	ip_hd->ip_sum = 0;
	for(int i = 0; i<len;i++){
		checksum += *p++;
	}

	checksum = (checksum >> 16) +(checksum & 0xffff);
	checksum += (checksum >> 16);
	ip_hd->ip_sum = (~checksum & 0xffff);
}

void TCP_checksum(struct rst_packet *rst_hd) {
	u_int16_t *p = (u_int16_t *)&(rst_hd->tcp_header);
	u_int16_t *tempip;
	u_int16_t datalen = (ntohs(rst_hd->ip4_header.ip_len)) - 20 ;
	u_int16_t len = datalen;
	u_int32_t checksum = 0;
	len >>= 1;
	rst_hd->tcp_header.th_sum = 0;
	for(int i =0; i<len;i++) {
		checksum += *p++;
	}

	if(datalen % 2 == 1) {
		checksum += *p++ & 0x00ff;
	}
	tempip = (u_int16_t *)(&rst_hd->ip4_header.ip_dst);
	for(int i=0;i<2;i++) {
		checksum += *tempip++;
	}
	tempip = (u_int16_t *)(&rst_hd->ip4_header.ip_src);
	for(int i=0;i<2;i++) {
		checksum += *tempip++;
	}
	checksum += htons(6);
	checksum += htons(datalen);
	checksum = (checksum >> 16) +(checksum & 0xffff);
	checksum += (checksum >> 16);
	rst_hd->tcp_header.th_sum = (~checksum & 0xffff);
}

void make_rst(struct rst_packet *rst) {
	rst->eth_header.ether_type = htons(ETHERTYPE_IP);

	rst->ip4_header.ip_v = 4;
	rst->ip4_header.ip_hl = 5;
	rst->ip4_header.ip_tos = 0x44;
	rst->ip4_header.ip_len = 0x0028;
	rst->ip4_header.ip_ttl = 0xff;
	rst->ip4_header.ip_p = IPPROTO_TCP;
	rst->ip4_header.ip_sum = htons(0xabcd);
	rst->ip4_header.ip_off = htons(IP_DF);

	rst->tcp_header.th_off = 5;
	rst->tcp_header.th_win = 0;
	rst->tcp_header.th_sum = 0;
	rst->tcp_header.th_urp = 0;
}

void get_my_dev(u_int8_t *ether, u_int8_t *ip, char *dev){
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	if(fd<0) perror("socket fail");
	strcpy(ifr.ifr_name, "ens33");
	if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0) perror("ioctl fail");  // get MAC address
	memcpy(ether, ifr.ifr_hwaddr.sa_data, 6);
	if(ioctl(fd,SIOCGIFADDR, &ifr)<0) perror("ioctl fail");  // get IP address
	memcpy(ip,&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 4*sizeof(*ip));
}

int main(int argc, char *argv[]) {
	int flag;
	if(argc != 2) {
		usage();
		return -1;
	}

	u_int8_t my_mac[6];
	u_int8_t my_ip[4];

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	get_my_dev(my_mac, my_ip, dev);

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	struct rst_packet rst_p;

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true) {
		flag = -1;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		struct ether_header* eth = (struct ether_header *)packet;
		eth->ether_type = ntohs(eth->ether_type);
		if(eth->ether_type == ETHERTYPE_IP){
			struct ip *ip4 = (struct ip *)(packet + 14);

			// if it is TCP packet			
			if(ip4->ip_p == IPPROTO_TCP){
				struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + 20);
				u_int16_t tcp_len = ntohs(ip4->ip_len) - 20;
				u_int16_t tcp_payload_len = tcp_len - tcp->th_off*4;
				u_int8_t *tcp_payload = (u_int8_t *)(packet + 14 + 20 + tcp->th_off*4);
				//printf("\nTCP Payload_len : %d\n", tcp_payload_len);
				u_int32_t tcp_seq = htonl(ntohl(rst_p.tcp_header.th_seq) + tcp_payload_len);
				if(tcp_payload_len !=  0 && memcmp(tcp_payload, get_str, strlen(get_str)) == 0) {
					flag = 1;
				}
				else {
					flag = 0;
				}
	
				// if it is not HTTP but TCP
				if((tcp->th_flags & TH_ACK) != 0 && ((tcp->th_flags & TH_RST)==0) && flag == 0) {
					
					//Forward RST					
					make_rst(&rst_p);
					rst_p.tcp_header.th_flags = TH_RST + TH_ACK;
					memcpy(&rst_p.eth_header.ether_shost, my_mac, 6);
					memcpy(&rst_p.eth_header.ether_dhost, &eth->ether_dhost, 6);
					memcpy(&rst_p.ip4_header.ip_src, &ip4->ip_src, 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_dst, 4);
					memcpy(&rst_p.ip4_header.ip_tos, &ip4->ip_tos, 2);

					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_dport, 2);
					
					IP_checksum(&rst_p.ip4_header);
					TCP_checksum(&rst_p);

					//printf("Send Forward RST_TCP\n");
					pcap_sendpacket(handle, (u_int8_t*)&rst_p, sizeof(struct rst_packet));
					
					//Backward RST
					rst_p.tcp_header.th_flags = TH_RST + TH_ACK;			
					memcpy(&rst_p.eth_header.ether_shost, my_mac, 6);
					memcpy(&rst_p.eth_header.ether_dhost, &eth->ether_shost, 6);
					memcpy(&rst_p.ip4_header.ip_src, &ip4->ip_dst, 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_src, 4);

					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_dport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_seq, &rst_p.tcp_header.th_ack, 4);
					memcpy(&rst_p.tcp_header.th_ack, &tcp_seq, 4);

					IP_checksum(&rst_p.ip4_header);
					TCP_checksum(&rst_p);

					//printf("Send Backward RST_TCP\n");
					pcap_sendpacket(handle, (u_int8_t*)&rst_p, sizeof(struct rst_packet));
				}
				
				// if it is HTTP
				if(((tcp->th_flags & TH_RST)==0) && flag == 1) {
					
					//Forward RST
					make_rst(&rst_p);
					rst_p.tcp_header.th_flags = TH_RST + TH_ACK;								
					memcpy(&rst_p.eth_header.ether_shost, my_mac, 6);
					memcpy(&rst_p.eth_header.ether_dhost, &eth->ether_dhost, 6);
					memcpy(&rst_p.ip4_header.ip_src, &ip4->ip_src, 4);
					memcpy(&rst_p.ip4_header.ip_dst, &ip4->ip_dst, 4);
					memcpy(&rst_p.tcp_header.th_sport, &tcp->th_sport, 2);
					memcpy(&rst_p.tcp_header.th_dport, &tcp->th_dport, 2);

					
					//printf("Send Forward RST_HTTP\n");
					pcap_sendpacket(handle, (u_int8_t*)&rst_p, sizeof(struct rst_packet));

					//Backward FIN
					void *redir_p = malloc(sizeof(rst_packet) + strlen(fake));
					struct rst_packet *fin_p = (struct rst_packet *)redir_p;				
					make_rst(fin_p);					
					fin_p->tcp_header.th_flags = TH_FIN + TH_ACK;
					fin_p->ip4_header.ip_len = 0x002f;
					
					memcpy(&fin_p->eth_header.ether_shost, my_mac, 6);
					memcpy(&fin_p->eth_header.ether_dhost, &eth->ether_shost, 6);
					memcpy(&fin_p->ip4_header.ip_src, &ip4->ip_dst, 4);
					memcpy(&fin_p->ip4_header.ip_dst, &ip4->ip_src, 4);
					
					memcpy(&fin_p->tcp_header.th_sport, &tcp->th_dport, 2);
					memcpy(&fin_p->tcp_header.th_dport, &tcp->th_sport, 2);
					memcpy(&fin_p->tcp_header.th_seq, &rst_p.tcp_header.th_ack, 4);
					memcpy(&fin_p->tcp_header.th_ack, &tcp_seq, 4);

					IP_checksum(&fin_p->ip4_header);
					TCP_checksum(fin_p);

					//printf("Send Backward FIN_HTTP\n");
					pcap_sendpacket(handle, (u_int8_t *)fin_p, sizeof(struct rst_packet) + strlen(fake) );
					free(redir_p);
					
				}
			}
		}
	}
	return 0;
}
