#include "send_arp.h"

void get_mac(u_int8_t *mac_addr, u_int8_t *interface) {
	int s,i;
	struct ifreq ifr;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	ioctl(s, SIOCGIFHWADDR, &ifr);
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	close(s);
}

void get_ip(u_int8_t *ip_addr, u_int8_t *interface) {
	int s;
	struct ifreq ifr;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);
	memcpy(ip_addr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDR_LEN);
	close(s);
}

void gen_arp_packet(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode) {
	struct ether_header *eptr;
	struct arp_header *aptr;
	int i;

	eptr = (struct ether_header *)malloc(sizeof(struct ether_header));
	aptr = (struct arp_header *)malloc(sizeof(struct arp_header));

	if(dst_mac != NULL)
		memcpy(eptr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
	else
		memcpy(eptr->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	memcpy(eptr->ether_shost, src_mac, ETHER_ADDR_LEN);
	eptr->ether_type = htons(ETHERTYPE_ARP);

	aptr->ar_hrd = htons(ARPHRD_ETHER);
	aptr->ar_pro = htons(ETHERTYPE_IP);
	aptr->ar_hln = 6;
	aptr->ar_pln = 4;
	aptr->ar_op = htons(opcode);
	memcpy(aptr->ar_sha, src_mac, ETHER_ADDR_LEN);
	memcpy(aptr->ar_sip, src_ip, IP_ADDR_LEN);
	if(dst_mac != NULL)
		memcpy(aptr->ar_tha, dst_mac, ETHER_ADDR_LEN);
	else
		memcpy(aptr->ar_tha, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	memcpy(aptr->ar_tip, dst_ip, IP_ADDR_LEN);

	memcpy(packet, eptr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), aptr, sizeof(struct arp_header));
}
