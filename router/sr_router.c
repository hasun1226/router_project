 /**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init( struct sr_instance* sr,
              int nat_status,
              time_t icmp_timeout,
              time_t tcp_established_timeout,
              time_t tcp_transmission_timeout)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

    if (sr->nat_status)
    {
        sr->nat = (struct sr_nat *)malloc(sizeof(struct sr_nat));
        sr_nat_init(sr->nat, icmp_timeout, tcp_established_timeout, tcp_transmission_timeout);
    }

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*frame_hdr_size gives the size of the ethernet header (in bytes)*/
  uint16_t frame_type = ethertype(packet);
  struct sr_if *out_interface = sr_get_interface(sr, interface);

  /* The packet is an IP packet*/
  if (frame_type == ethertype_ip) {
      ip_sanity_check(packet);
      if (!sr->nat_status) handle_ip(sr, packet, len, out_interface);
      else nat_process(sr, packet, len, interface);
  }

  /* The packet is an ARP packet */
  else if (frame_type == ethertype_arp)
  {
      sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

      /* The ARP packet is a reply */
      if (ntohs(arp_header->ar_op) == arp_op_reply) handle_arp_reply(sr, packet, out_interface);

      /* Only send an arp reply if the target IP address is one of the router's IP addresses */
      if (ntohs(arp_header->ar_op)== arp_op_request && contains_interface_ip(sr, arp_header->ar_tip))
      sr_send_arp_reply(sr, packet, sizeof(packet), out_interface);
  }

  /* Received packet other than IP packet or an ARP packet. */
  else fprintf(stderr, "Indicator not in range");
}/* end sr_ForwardPacket */


/* Do sanity check on IP packet. */
void ip_sanity_check(uint8_t *packet) {
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    int ip_hdr_bytelen = ip_header->ip_hl * WORD_TO_BYTE;
    uint16_t ip_sum_copy = ip_header->ip_sum;
    ip_header->ip_sum = 0;

    if((ip_header->ip_v != 4) || (ip_header->ip_hl < 5) || (ip_sum_copy != cksum(ip_header, ip_hdr_bytelen)))
    {
        fprintf(stderr,"The ip_header is not valid\n");
        return;
    } /* end Sanity check for IP header */

    /* Recover the ip_sum. */
    ip_header->ip_sum = ip_sum_copy;
}
/* Calculate checksum for TCP header */
uint16_t tcp_cksum(uint8_t *packet) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    uint16_t tcp_len = ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * WORD_TO_BYTE;

    uint8_t *data = malloc (sizeof(pseudo_tcp_hdr_t) + tcp_len);
    pseudo_tcp_hdr_t *pseudo_tcp = (pseudo_tcp_hdr_t *) data;

    pseudo_tcp->src_add = ip_hdr->ip_src;
    pseudo_tcp->dst_add = ip_hdr->ip_dst;
    pseudo_tcp->reserved = 0x0;
    pseudo_tcp->ip_p = ip_protocol_tcp;
    pseudo_tcp->length = htons(tcp_len);

    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memcpy(data + sizeof(pseudo_tcp_hdr_t), tcp_hdr, tcp_len);
    sr_tcp_hdr_t *ck_tcp_hdr = (sr_tcp_hdr_t *) (data + sizeof(pseudo_tcp_hdr_t));
    ck_tcp_hdr->tcp_sum = 0;

    uint16_t result = cksum(data, sizeof(pseudo_tcp_hdr_t) + tcp_len);
    free(data);
    return result;
}


/*
 * Handle the IP packet with Network Address Translation protocol
 */
void nat_process(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    /* Prepare a packet buf that will be routed */
    uint8_t *buf = (uint8_t *) malloc(len);

    if(!buf)
    {
        fprintf(stderr, "malloc in IP packet forwarding failed\n");
        return;
    }

    memcpy(buf, packet, len);

    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
    int ip_hdr_bytelen = ip_header->ip_hl * WORD_TO_BYTE;

    if (ip_header->ip_p == ip_protocol_icmp)
    {
	fprintf(stderr, "NAT process: icmp packet received\n");
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
/*        uint16_t icmp_sum_copy = icmp_hdr->icmp_sum; */

        /* Sanity check on ICMP header
        if (icmp_hdr->icmp_type != ICMP_ECHO || icmp_hdr->icmp_type != ICMP_ECHO_REPLY ||
            icmp_sum_copy != cksum(icmp_hdr, ntohs(ip_header->ip_len) - ip_hdr_bytelen))
            {
                fprintf(stderr, "NAT process: ICMP header sanity check failed\n");
                return;
            }

        icmp_hdr->icmp_sum = icmp_sum_copy; */

        /* Packet is from the internal interface */
        if (!strcmp(interface, (sr->nat)->int_if_name))
        {
	    fprintf(stderr, "Packet received at internal interface\n");
	    print_hdrs(buf, len);
	    struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, ip_header->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);

            /* No such mapping, insert it */
            if (!mapping) {
		printf("No mapping\n");
                mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
	    }

printf("Rewriting outgoing packet\n");
            /* Rewrite outgoing packet */
            ip_header->ip_src = sr_get_interface(sr, DEFAULT_EXTERNAL_INTERFACE)->ip;
            icmp_hdr->icmp_id = mapping->aux_ext;
	    icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_header->ip_len) - ip_hdr_bytelen);
    	    ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

print_hdrs(buf, len);
	    printf("Finished Rewriting outgoing packet\n");

            free(mapping);
            check_and_send(sr, buf, len, (sr->nat)->int_if_name);
printf("Sent the outgoing packet\n");
        }

        /* Packet is from the external interface */
        else
        {
	    printf("Received packet from external interface\n");
print_hdrs(buf, len);
            struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, icmp_hdr->icmp_id, nat_mapping_icmp);

            /*
             * No such mapping, drop it? send ICMP echo reply? send ICMP Port Unreachable? For now, we assume ICMP echo reply
             * Piazza post says "if no mapping is found, then you can safely assume this ping request is targeted at the router itself"
             */
            if (!mapping)
            {
                sr_send_icmp_reply(sr, packet, len, sr_get_interface(sr, interface));
                /* sr_send_icmp_t3(sr, ICMP_PORT_UNREACHABLE, packet, len, sr_get_interface(sr, interface)); */
                return;
            }
printf("Rewriting incoming packet\n");

            /* Rewrite the packet going to internal interface */
            ip_header->ip_dst = mapping->ip_int;
            icmp_hdr->icmp_id = mapping->aux_int;
	    icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_header->ip_len) - ip_hdr_bytelen);
	    ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

print_hdrs(buf, len);
            printf("Finished Rewriting incoming packet\n");

            free(mapping);
            check_and_send(sr, buf, len, DEFAULT_EXTERNAL_INTERFACE);
printf("Sent the incoming packet\n");
        }

    }

    else if (ip_header->ip_p == ip_protocol_tcp)
    {
        sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* Sanity check on TCP header */
        if (tcp_hdr->tcp_sum != tcp_cksum(buf))
        {
            fprintf(stderr, "NAT process: TCP header sanity check failed\n");
            return;
        }

        /* Packet is outbound(from the internal interface) insert or lookup mapping */
        if (!strcmp(interface, (sr->nat)->int_if_name))
        {
            struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat, ip_header->ip_src, tcp_hdr->src_port, nat_mapping_tcp);

            if (!mapping)
                mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src, tcp_hdr->src_port, nat_mapping_tcp);

            /* Rewrite outgoing packet */
            ip_header->ip_src = sr_get_interface(sr, DEFAULT_EXTERNAL_INTERFACE)->ip;
            tcp_hdr->src_port = mapping->aux_ext;
            tcp_hdr->tcp_sum = tcp_cksum(buf);
            ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

            /* Update time of the mapping */
            update_tcp_connection(mapping, ip_header->ip_dst, tcp_hdr->dst_port, tcp_hdr, 0);
            free(mapping);
            check_and_send(sr, buf, len, (sr->nat)->int_if_name);
        }

        /* Packet is from the external interface */
        else
        {
            struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, tcp_hdr->dst_port, nat_mapping_tcp);

            /* No such mapping and not a SYN(for simultaneous open?), drop it */
            if (tcp_hdr->flag != SYN && mapping == NULL) return;

            /* Rewrite incoming packet */
            ip_header->ip_dst = mapping->ip_int;
            tcp_hdr->dst_port = mapping->aux_int;
            tcp_hdr->tcp_sum = tcp_cksum(buf);
            ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

            /* Update time of the mapping */
            update_tcp_connection(mapping, ip_header->ip_src, tcp_hdr->src_port, tcp_hdr, 1);
            free(mapping);
            check_and_send(sr, buf, len, DEFAULT_EXTERNAL_INTERFACE);
        }
    }
}


/* Handle when the router received an IP packet */
void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *out_interface) {
      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
      sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /* Handle the packet for this router. */
      if (contains_interface_ip(sr, ip_header->ip_dst))
      {
          /* Send echo reply in correspond to ICMP echo request. */
          if (ip_header->ip_p == ip_protocol_icmp && icmp_header->icmp_type == ICMP_ECHO)
            sr_send_icmp_reply(sr, packet, len, out_interface);

          /* Send ICMP Port Unreachable in correspond to TCP/UDP packet. */
          else if (ip_header->ip_p == ip_protocol_udp || ip_header->ip_p == ip_protocol_tcp)
              sr_send_icmp_t3(sr, ICMP_PORT_UNREACHABLE, packet, len, out_interface);
      }

      /* Handle the packet that is outbound of router. */
      else
      {
         /* Prepare a packet buf that will be sent to nexthop */
         uint8_t *buf = (uint8_t *) malloc(len);
         if(!buf)
         {
             fprintf(stderr, "malloc in IP packet forwarding failed\n");
             return;
         }

         memcpy(buf, packet, len);
         struct sr_ip_hdr *buf_ip_hdr = (struct sr_ip_hdr *) (buf + sizeof(sr_ethernet_hdr_t));

         /* Decrement ttl and compute checksum for the outgoing buf */
         buf_ip_hdr->ip_ttl--;
         buf_ip_hdr->ip_sum = 0;
         buf_ip_hdr->ip_sum = cksum(buf_ip_hdr, buf_ip_hdr->ip_hl * WORD_TO_BYTE);

         check_and_send(sr, buf, len, out_interface->name);
         free(buf);
      }
}


/* Handle when the router received an ARP reply packet */
void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *out_interface) {
    /* Cache the ip address */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, ethernet_header->ether_shost, arp_header->ar_sip);

    /* The request queue exists */
    if (request)
    {
        struct sr_packet *curr_pkt = request->packets;

        while (curr_pkt)
        {
            /* Prepare a packet buf that will be sent to nexthop */
            uint8_t *buf = (uint8_t *) malloc(curr_pkt->len);
            if(!buf)
            {
              	fprintf(stderr, "malloc in IP packet forwarding failed\n");
              	return;
            }

            memcpy(buf, curr_pkt->buf, curr_pkt->len);
            struct sr_ethernet_hdr *buf_eth_hdr = (struct sr_ethernet_hdr *) buf;
            struct sr_ip_hdr *buf_ip_hdr = (struct sr_ip_hdr *) (buf + sizeof(sr_ethernet_hdr_t));
            struct sr_rt *nexthop = sr_lpm(sr, buf_ip_hdr->ip_dst);
            struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), (nexthop->gw).s_addr);

           	/* Add MAC addresses to Ethernet frame */
           	memcpy(buf_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
           	memcpy(buf_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

           	/* Compute the checksum for outgoing buf*/
           	buf_ip_hdr->ip_sum = 0;
           	buf_ip_hdr->ip_sum = cksum(buf_ip_hdr, buf_ip_hdr->ip_hl * WORD_TO_BYTE);

            sr_send_packet(sr, buf, curr_pkt->len, out_interface->name);
         	free(buf);
            curr_pkt = curr_pkt->next;
        }
    }
}


/* Consults the arpcache before either 1) Sending the given packet
 *				or     2) Caching the given packet (if the destination IP isn't in the arpcache)
 */
void check_and_send(struct sr_instance* sr, uint8_t *packet, unsigned int len, const char* iface) {
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	struct sr_rt *nexthop = sr_lpm(sr, ip_header->ip_dst);
    struct sr_if* out_interface = sr_get_interface (sr, iface);

    /* Send ICMP message if TTL field is 0 */
    if (ip_header->ip_ttl == 0)
        sr_send_icmp_t3(sr, ICMP_TIME_EXCEEDED, packet, len, out_interface);

	/* There is no match from performing LPM */
    else if (!nexthop)
        sr_send_icmp_t3(sr, ICMP_NET_UNREACHABLE, packet, len, out_interface);

    else
    {
        uint32_t nexthop_ip = (nexthop->gw).s_addr;
	    struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), nexthop_ip);
	    struct sr_if *source_interface = sr_get_interface(sr, nexthop->interface);

        /* ARP cache has the MAC address for the ip address */
        if (entry)
        {
            struct sr_ethernet_hdr *buf_eth_hdr = (struct sr_ethernet_hdr *) packet;

            /* Add MAC addresses to Ethernet frame */
            memcpy(buf_eth_hdr->ether_shost, source_interface->addr, ETHER_ADDR_LEN);
            memcpy(buf_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, source_interface->name);

            /* Free the memory allocated in sr_arpcache_lookup */
            free(entry);
        }

        /* Need to send ARP request for IP -> MAC mapping. Queue the request */
        else
        {
            struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), nexthop_ip, packet, len, (char *) iface);
            handle_arpreq(sr, req, source_interface);
        }
    }
}


/*
 * Check the destination ip with the interface list ip
 * Returns 1 if found otherwise 0.
 */
int contains_interface_ip(struct sr_instance* sr, uint32_t ip)
{
    struct sr_if *my_interface = sr->if_list;

    while (my_interface != NULL)
    {
        if (my_interface->ip == ip)
        {
            return 1;
        }
        my_interface = my_interface->next;
    }

    return 0;
}

/* Construct an ARP request and send it. */
void sr_send_arp_request(struct sr_instance *sr,  struct sr_if *out_interface, struct sr_arpreq *request)
{
    /*  Allocate memory to create the packet = ethernet frame + header of the arp request */

    unsigned int packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *request_packet = (uint8_t *)malloc(packet_length);

    if (request_packet== NULL)
    {
        fprintf(stderr,"Failed to allocate memory to arp request\n");
    }

    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *) request_packet;
    sr_arp_hdr_t *request_arp_hdr = (sr_arp_hdr_t *) (request_packet + sizeof(sr_ethernet_hdr_t)) ;

    /* initialize ethernet header */
    memcpy(request_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    memset(request_eth_hdr->ether_dhost, BROADCAST_ADDR, ETHER_ADDR_LEN);
    request_eth_hdr->ether_type = htons(ethertype_arp);

    /* initialize arp request header */
    request_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    request_arp_hdr->ar_pro = htons(ethertype_ip);
    request_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    request_arp_hdr->ar_pln = sizeof(uint32_t);
    request_arp_hdr->ar_op = htons(arp_op_request);
    memcpy(request_arp_hdr->ar_sha, out_interface->addr, ETHER_ADDR_LEN);
    request_arp_hdr->ar_sip = out_interface->ip;
    memset(request_arp_hdr->ar_tha, ARP_TARGET, ETHER_ADDR_LEN);
    request_arp_hdr->ar_tip = request->ip;

    /* send arp request */
    sr_send_packet(sr, request_packet, packet_length, out_interface->name);
    free(request_packet);
}

/* Construct an ARP reply and send it back. */
void sr_send_arp_reply(struct sr_instance *sr, uint8_t * packet, unsigned int length, struct sr_if *source_interface)
{
    unsigned int packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *reply_packet = (uint8_t *)malloc(packet_length);

    if (reply_packet == NULL)
    {
        fprintf(stderr,"Failed to allocated memory for arp reply\n");
    }

    sr_arp_hdr_t *original_arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_packet;
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));

    /* initialize ethernet header*/
    memcpy(reply_eth_hdr->ether_dhost, original_arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, source_interface->addr, ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = htons(ethertype_arp);

    /* initialize arp reply header */
    reply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    reply_arp_hdr->ar_pro = htons(ethertype_ip);
    reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    reply_arp_hdr->ar_pln = sizeof(uint32_t);
    reply_arp_hdr->ar_op  = htons(arp_op_reply);
    reply_arp_hdr->ar_sip = source_interface->ip;
    reply_arp_hdr->ar_tip = original_arp_hdr->ar_sip;
    memcpy(reply_arp_hdr->ar_sha, source_interface->addr, ETHER_ADDR_LEN);
    memcpy(reply_arp_hdr->ar_tha, original_arp_hdr->ar_sha, ETHER_ADDR_LEN);

    /* send arp reply */
    sr_send_packet(sr, reply_packet, packet_length, source_interface->name);
    free(reply_packet);
}

/* Sends ICMP reply to the source address */
void sr_send_icmp_reply(struct sr_instance *sr, uint8_t * packet, unsigned int len, struct sr_if *out_interface)
{
    sr_ethernet_hdr_t *original_eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /*Create a new packet*/
    uint8_t *request_packet = (uint8_t *) malloc(len);
    memcpy(request_packet, packet, len);

    /* Prepare a new Ethernet Frame */
    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *) request_packet;
    memcpy(request_eth_hdr->ether_shost, original_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(request_eth_hdr->ether_dhost, original_eth_hdr->ether_shost, ETHER_ADDR_LEN);

    /* Prepare a new ip header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (request_packet + sizeof(sr_ethernet_hdr_t));
    ip_header->ip_ttl = DEFAULT_TTL;                              /* time to live */
    ip_header->ip_dst = original_ip_header->ip_src;               /* destination address */
    ip_header->ip_src = original_ip_header->ip_dst;               /* source address */
    ip_header->ip_p = ip_protocol_icmp;                           /* protocol */
    ip_header->ip_sum = 0;                                        /* checksum */
    int ip_hdr_bytelen = ip_header->ip_hl * WORD_TO_BYTE;
    ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

    /* Initialize ICMP header */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (request_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;

    /* Computes checksum for the outgoing request_packet */
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_header->ip_len) - ip_hdr_bytelen);

    check_and_send(sr, request_packet, len, out_interface->name);
    free(request_packet);
}

/* Fills out the fields in ICMP type 3 header */
void icmp_t3_fill(sr_icmp_t3_hdr_t *icmp_header, int indicator)
{
    icmp_header->icmp_type = 3;
    icmp_header->icmp_sum = 0;


    switch (indicator)
    {
      case ICMP_NET_UNREACHABLE:
           icmp_header->icmp_code = 0;
           break;
      case ICMP_HOST_UNREACHABLE:
           icmp_header->icmp_code = 1;
           break;
      case ICMP_PORT_UNREACHABLE:
           icmp_header->icmp_code = 3;
           break;
      case ICMP_TIME_EXCEEDED:
           icmp_header->icmp_type = 11;
           icmp_header->icmp_code = 0;
           break;
      default:
           fprintf(stderr, "Invalid type 3 indicator\n");
           return;
    }

    sr_ip_hdr_t *encap_ip = (sr_ip_hdr_t *) icmp_header->data;
    encap_ip->ip_sum = 0;
    encap_ip->ip_sum = cksum(encap_ip, encap_ip->ip_hl * WORD_TO_BYTE);
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t));
    return;
}

/* Receives the indicator for the ICMP Type 3 message and sends it to the source address */
void sr_send_icmp_t3(struct sr_instance *sr, int indicator, uint8_t * packet, unsigned int len, struct sr_if *out_interface)
{
    sr_ethernet_hdr_t *original_eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Create an outgoing packet */
    uint8_t *request_packet = (uint8_t *) malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));

    /* Fill out the new Ethernet Frame */
    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *) request_packet;
    memcpy(request_eth_hdr->ether_shost, original_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(request_eth_hdr->ether_dhost, original_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    request_eth_hdr->ether_type = original_eth_hdr->ether_type;

    /* Fill out the new IP Frame */
    sr_ip_hdr_t *request_ip_header = (sr_ip_hdr_t *) (request_packet + sizeof(sr_ethernet_hdr_t));
    memcpy(request_ip_header, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    request_ip_header->ip_ttl = DEFAULT_TTL;
    request_ip_header->ip_p = ip_protocol_icmp;
    request_ip_header->ip_id = 0;
    request_ip_header->ip_sum = 0;
    request_ip_header->ip_dst = original_ip_header->ip_src;
    request_ip_header->ip_src = (indicator == ICMP_PORT_UNREACHABLE) ? original_ip_header->ip_dst : out_interface->ip;

    /* Fill out the new ICMP header */
    sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *) (request_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memcpy(icmp_header->data, original_ip_header, ICMP_DATA_SIZE);
    icmp_t3_fill(icmp_header, indicator);

    /* Compute the IP header checksum */
    int ip_hdr_bytelen = request_ip_header->ip_hl * WORD_TO_BYTE;
    request_ip_header->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + ip_hdr_bytelen);
    request_ip_header->ip_sum = cksum(request_ip_header, ip_hdr_bytelen);

    len = sizeof(sr_icmp_t3_hdr_t) + ip_hdr_bytelen + sizeof(sr_ethernet_hdr_t);
    check_and_send(sr, request_packet, len, out_interface->name);
    free(request_packet);
}

/*
 * Finds the longest prefix matching with the given address.
 * Returns the ip of the the longest matching entry in the routing table.
 * A null pointer is returned if no matching entry can be found.
 */
struct sr_rt *sr_lpm(struct sr_instance* sr, uint32_t addr)
{
	struct sr_rt *rt_walker = sr->routing_table;
	struct sr_rt *matching_entry = 0;
	unsigned long lmatching_length = 0;
	uint32_t mask, entry_addr;

	while(rt_walker) {
        entry_addr = rt_walker->dest.s_addr;
        mask = rt_walker->mask.s_addr;

        /* Get the length of the mask */
        int mask_length, i;
        mask_length = 0;

        for (i = 0; i < (sizeof(uint32_t) * 8); i++)
        {
            /* In binary form, the masks's s_addr is simply a sequence of 1's followed
               by a sequence of 0's. So, the number of 1s is the length of the mask */
            if (!(mask & (1 << ((sizeof(uint32_t) * 8) - i - 1)))) break;
            mask_length++;
        }

		if (((entry_addr & mask) == (addr & mask)) && (mask_length >= lmatching_length))
        {
            /* The IP of rt_walker has a longer prefix match with the given address */
			lmatching_length = mask_length;
			matching_entry = rt_walker;
		}

		rt_walker = rt_walker->next;
	}

	return matching_entry;
}

