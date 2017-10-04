#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<netinet/if_ether.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<string.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#define IP_ADDR_LEN 4

struct arp_header{
    u_int16_t ar_hrd;
    u_int16_t ar_pro;
    u_int8_t ar_hln;
    u_int8_t ar_pln;
    u_int16_t ar_op;
    u_int8_t ar_sha[6];
    u_int8_t ar_sip[4];
    u_int8_t ar_tha[6];
    u_int8_t ar_tip[4];
};

void get_mac(u_int8_t *mac_addr, u_int8_t *interface);
void get_ip(u_int8_t *ip_addr, u_int8_t *interface);
void gen_arp_packet(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode);
