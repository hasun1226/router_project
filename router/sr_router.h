/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define BROADCAST_ADDR 0xFF
#define ARP_TARGET 0x00

#define ICMP_ECHO_REPLY 0
#define ICMP_NET_UNREACHABLE 1
#define ICMP_PORT_UNREACHABLE 2
#define ICMP_HOST_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 4
#define ICMP_ECHO 8
#define DEFAULT_TTL 64
#define IPV4 4
#define WORD_TO_BYTE 4
#define	IP_DF 0x4000

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    int nat;      /* NAT status */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void ip_sanity_check(uint8_t *packet);
void nat_process(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *out_interface);
void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *out_interface);
void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *out_interface);
void check_and_send(struct sr_instance* sr, uint8_t *packet, unsigned int len, const char* iface);
void sr_send_arp_request(struct sr_instance *sr, struct sr_if *out_interface, struct sr_arpreq *request);
void sr_send_arp_reply(struct sr_instance *sr, uint8_t * packet, unsigned int length, struct sr_if *source_interface);
void sr_send_icmp_reply(struct sr_instance *sr, uint8_t * packet, unsigned int len, struct sr_if *out_interface);
void icmp_t3_fill(sr_icmp_t3_hdr_t *icmp_header, int indicator);
void sr_send_icmp_t3(struct sr_instance *sr, int indicator, uint8_t * packet, unsigned int len, struct sr_if *out_interface);
int contains_interface_ip(struct sr_instance* sr, uint32_t ip);
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t addr);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
