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

int contains_interface_ip(struct sr_instance* sr, uint32_t ip);
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t addr);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
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
  printf("ip %d, arp %d\n", frame_type == ethertype_ip, frame_type == ethertype_arp);
  /* The packet is an IP packet*/
  if (frame_type == ethertype_ip) {
	printf("It is an IP packet\n");
      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
      sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      /* Sanity check on IP header */
      int ip_hdr_bytelen = ip_header->ip_len * WORD_TO_BYTE;
      uint16_t ip_sum_copy = ip_header->ip_sum;
      ip_header->ip_sum = 0;

      if((ip_header->ip_v != 4) || (ip_header->ip_hl < 5) || (ip_sum_copy != cksum(ip_header, ip_hdr_bytelen)))
      {
          /* Packet is dropped */
          fprintf(stderr,"The ip_header is not valid\n");
          return;
      } /* end Sanity check */

      /* Send ICMP message if TTL field is 0 */
      if (ip_header->ip_ttl == 0)
      {
          struct sr_if *out_interface = sr_get_interface(sr,interface);
          printf("Sending ICMP TIME EXCEEDED message\n");
          sr_send_icmp(sr, ICMP_TIME_EXCEEDED, packet, out_interface);
          return;
      }
	printf("Received packet has right checksum and still living\n");

      /* Check the packet to see if it's for me or not for me */
      if (contains_interface_ip(sr, ip_header->ip_dst))
      {
          /* The packet is for me. If it's an ICMP echo request, then send an echo reply */
          struct sr_if *out_interface = sr_get_interface(sr,interface);
	printf("the packet is for the router\n");
          if (ip_header->ip_p == ip_protocol_icmp && icmp_header->icmp_type == ICMP_ECHO)
          {
              /* Send echo reply */
              printf("Sending ICMP ECHO REPLY\n");
              sr_send_icmp(sr, ICMP_ECHO_REPLY, packet, out_interface);
              return;
          }

          else
          {
              /* It is TCP/UDP Send ICMP port unreachable */
              printf("Sending ICMP PORT UNREACHABLE message\n");
              sr_send_icmp_t3(sr, ICMP_PORT_UNREACHABLE, packet, out_interface);
              return;
          }

      }

      else
      {
        /* The packet isn't for me, so check the routing table
         and perform LPM and foward it to the next hop */
         struct sr_rt *nexthop = sr_lpm(sr, ip_header->ip_dst);
	printf("the packet is not for the router\n");
         /* There is no match from performing LPM */
         if (!nexthop)
         {
            struct sr_if *out_interface = sr_get_interface(sr,interface);
            printf("Sending ICMP NET UNREACHABLE message, no nexthop\n");
            sr_send_icmp_t3(sr, ICMP_NET_UNREACHABLE, packet, out_interface);
            return;
         }

         /* There is a match */
	 printf("nexthop exists\n");
         uint32_t nexthop_ip = (nexthop->dest).s_addr;
         struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), nexthop_ip);
         struct sr_if* out_interface = sr_get_interface(sr, nexthop->interface);

         /* ARP cache has the MAC address for the ip address */
         if(entry != NULL)
         {
             unsigned char *nexthop_mac = entry->mac;

             /* Prepare a packet buf that will be sent to nexthop */
             uint8_t *buf;

             if((buf = (uint8_t *) malloc(len)) == NULL)
             {
                fprintf(stderr, "malloc in IP packet forwarding failed\n");
             }

             memcpy(buf, packet, len);
             struct sr_ethernet_hdr *buf_eth_hdr = (struct sr_ethernet_hdr *) buf;
             /* Add MAC addresses to Ethernet frame */
             memcpy(buf_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
             memcpy(buf_eth_hdr->ether_dhost, nexthop_mac, ETHER_ADDR_LEN);

             /* Compute the checksum for outgoing buf*/
             struct sr_ip_hdr *buf_ip_hdr = (struct sr_ip_hdr *) (buf + sizeof(sr_ethernet_hdr_t));
             int ip_hdr_bytelen = buf_ip_hdr->ip_len * WORD_TO_BYTE;
             buf_ip_hdr->ip_sum = 0;
             buf_ip_hdr->ip_sum = cksum(buf_ip_hdr, ip_hdr_bytelen);

             /* Decrement ttl for the outgoing buf */
             buf_ip_hdr->ip_ttl--;

             printf("TTL: " + buf_ip_hdr->ip_ttl, "\nSending the packet\n");
             sr_send_packet(sr, buf, len, out_interface->name);
             /* Free the memory allocated in sr_arpcache_lookup */
             free(entry);
         }

         /* Need to send ARP request for IP -> MAC mapping. Queue the request */
         else
         {
             sr_arpcache_queuereq(&(sr->cache), nexthop_ip, packet,
                                  len, out_interface->name);
	     printf("Packet is moved to the arp cache request queue\n");
            /* Packet is moved to the arp cache request queue */
             free(packet);
         }

      }

  }

  /* The packet is an ARP packet */
  else if (frame_type == ethertype_arp) {
      /* Get the ARP packet while ignoring the frame header in front of the packet */
      sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;

      printf("arp request %d, arp reply %d\n", arp_header->ar_op==htons(arp_op_request), arp_header->ar_op==htons(arp_op_reply));
      /* The ARP packet is a reply */
      if (arp_header->ar_op == htons(arp_op_reply))
      {
          printf("Received an ARP reply\n");
          /* Cache the ip address */
          struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, ethernet_header->ether_shost, arp_header->ar_sip);

          /* The request queue exists */
          if (request)
          {
              struct sr_packet *curr_pkt = request->packets;

              while (curr_pkt)
              {
                  /* Send all packets on the request->packets linked list */
                  sr_send_packet(sr, curr_pkt->buf, curr_pkt->len, curr_pkt->iface);
                  curr_pkt = curr_pkt->next;
              }

              /* Destroy the request queue */
              sr_arpreq_destroy(&(sr->cache), request);
              printf("The packets have been sent and destroyed\n");
          }

      }

      /* The ARP packet is a request and if it is in one of my interfaces then reply */
      if (arp_header->ar_op == htons(arp_op_request))
      {
          printf("Sending the ARP reply\n");
          sr_send_arp_reply(sr, packet, sizeof(packet), sr_get_interface(sr, interface));
      }

  }

  else
  {
    /* Received something that's not an IP packet or an ARP packet
       Probably not supposed to happen */
    fprintf(stderr, "Indicator not in range");
  }

}/* end sr_ForwardPacket */

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
    sr_arp_hdr_t *request_arp_hdr = (sr_arp_hdr_t *) (request_packet + sizeof(sr_ethernet_hdr_t));

    /* initialize ethernet header */
    memcpy(request_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    memset(request_eth_hdr->ether_dhost, BROADCAST_ADDR, ETHER_ADDR_LEN);
    request_eth_hdr->ether_type = htons(ethertype_arp);

    /* initialize arp request header */
    request_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    request_arp_hdr->ar_pro = htons(ethertype_arp);
    request_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    request_arp_hdr->ar_pln = sizeof(uint32_t);
    request_arp_hdr->ar_op = htons(arp_op_request);
    memcpy(request_arp_hdr->ar_sha, out_interface, ETHER_ADDR_LEN);
    request_arp_hdr->ar_sip = out_interface->ip;
    memset(request_arp_hdr->ar_tha, ARP_TARGET, ETHER_ADDR_LEN);
    request_arp_hdr->ar_tip = request->ip;

    /* send arp request */
    printf("sending arp request");
    print_hdrs(request_packet, packet_length);
    sr_send_packet(sr, request_packet, packet_length, out_interface->name);
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

     sr_ethernet_hdr_t *original_eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_arp_hdr_t *original_arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_packet;
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));

    /* initialize ethernet header*/
    memcpy(reply_eth_hdr->ether_dhost, original_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, source_interface->addr, ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = original_eth_hdr->ether_type;

    /* initialize arp reply header */
    memcpy(reply_arp_hdr, original_arp_hdr, sizeof(sr_arp_hdr_t));
    reply_arp_hdr->ar_hrd = original_arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = original_arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = original_arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = original_arp_hdr->ar_pln;
    reply_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(reply_arp_hdr->ar_tha, original_arp_hdr->ar_sha, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = source_interface->ip;
    memcpy(reply_arp_hdr->ar_sha, source_interface->addr, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = original_arp_hdr->ar_sip;

    /* send arp request */
    print_hdrs(reply_packet, packet_length);
    sr_send_packet(sr, reply_packet, packet_length, source_interface->name);
printf("arp_reply sent successfully\n");
    free(reply_packet);

}

/* Receives the indicator for the ICMP message and sends it to the source address */
void sr_send_icmp(struct sr_instance *sr, int indicator, uint8_t * packet, struct sr_if *out_interface)
{
    sr_ethernet_hdr_t *original_eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /*Create a new packet*/
    unsigned int icmp_header_length = sizeof(sr_icmp_hdr_t);
    unsigned int new_packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_header_length;
    uint8_t *request_packet = (uint8_t *) malloc(new_packet_length);

    /* Prepare a new Ethernet Frame */
    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *) request_packet;
    memcpy(request_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    memcpy(request_eth_hdr->ether_dhost, original_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    request_eth_hdr->ether_type = ethertype_ip;

    /* Prepare a new ip header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (request_packet + sizeof(request_eth_hdr));
    ip_header->ip_hl = sizeof(sr_icmp_hdr_t);                     /* header length */
    ip_header->ip_v = IPV4;                                       /* version */
    ip_header->ip_tos = 0;                                        /* type of service */
    ip_header->ip_len = sizeof(sr_ip_hdr_t) + icmp_header_length; /* total length */
    ip_header->ip_id = original_ip_header->ip_id;                 /* identification */
    ip_header->ip_off = htons(IP_DF);                             /* fragment offset field */
    ip_header->ip_ttl = DEFAULT_TTL;                              /* time to live */
    ip_header->ip_p = ip_protocol_icmp;                           /* protocol */
    ip_header->ip_sum = 0;                                        /* checksum */
    ip_header->ip_src = original_ip_header->ip_dst;               /* source address */
    ip_header->ip_dst = original_ip_header->ip_src;               /* destination address */

    struct sr_rt *routing_table_entry = sr_lpm(sr, original_ip_header->ip_dst);
    int ip_hdr_bytelen = ip_header->ip_len * WORD_TO_BYTE;

    if (!routing_table_entry)
    {
        fprintf(stderr, "no router entry found");
        return;
    }

    struct sr_if *new_interface = sr_get_interface(sr, routing_table_entry->interface);
    ip_header->ip_src = new_interface->ip;

    /* Initialize ICMP header */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (request_packet + sizeof(&request_eth_hdr) + sizeof(&ip_header));

    switch (indicator)
    {
      case ICMP_ECHO_REPLY:
           icmp_hdr->icmp_type = 0;

      case ICMP_TIME_EXCEEDED:
           icmp_hdr->icmp_type = 11;
           icmp_hdr->icmp_code = 0;

      default: fprintf(stderr, "Invalid indicator\n");
    }

    /* Computes checksum for the outgoing request_packet */
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_header->ip_len) - ip_hdr_bytelen);
    ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

    printf("sending ICMP packet\n");
    sr_send_packet(sr, request_packet, new_packet_length, out_interface->name);
    free(request_packet);
}

/* Receives the indicator for the ICMP Type 3 message and sends it to the source address */
void sr_send_icmp_t3(struct sr_instance *sr, int indicator, uint8_t * packet, struct sr_if *out_interface)
{
    sr_ethernet_hdr_t *original_eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /*Create a new packet*/
    unsigned int icmp_header_length = sizeof(sr_icmp_hdr_t);
    unsigned int new_packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_header_length;
    uint8_t *request_packet = (uint8_t *) malloc(new_packet_length);

    /* Prepare a new Ethernet Frame */
    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *) request_packet;
    memcpy(request_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    memcpy(request_eth_hdr->ether_dhost, original_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    request_eth_hdr->ether_type = ethertype_ip;

    /* Prepare a new ip header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (request_packet + sizeof(request_eth_hdr));
    ip_header->ip_hl = sizeof(sr_icmp_hdr_t);                     /* header length */
    ip_header->ip_v = IPV4;                                       /* version */
    ip_header->ip_tos = 0;                                        /* type of service */
    ip_header->ip_len = sizeof(sr_ip_hdr_t) + icmp_header_length; /* total length */
    ip_header->ip_id = original_ip_header->ip_id;                 /* identification */
    ip_header->ip_off = htons(IP_DF);                             /* fragment offset field */
    ip_header->ip_ttl = DEFAULT_TTL;                              /* time to live */
    ip_header->ip_p = ip_protocol_icmp;                           /* protocol */
    ip_header->ip_sum = 0;                                        /* checksum */
    ip_header->ip_src = original_ip_header->ip_dst;               /* source address */
    ip_header->ip_dst = original_ip_header->ip_src;               /* destination address */

    struct sr_rt *routing_table_entry = sr_lpm(sr, original_ip_header->ip_dst);
    int ip_hdr_bytelen = ip_header->ip_len * WORD_TO_BYTE;

    if (!routing_table_entry)
    {
        fprintf(stderr, "no router entry found");
        return;
    }

    struct sr_if *new_interface = sr_get_interface(sr, routing_table_entry->interface);
    ip_header->ip_src = new_interface->ip;

    /* Initialize ICMP header */
    sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *) (request_packet + sizeof(&request_eth_hdr) + sizeof(&ip_header));
    icmp_t3_hdr->icmp_type = 3;
    icmp_t3_hdr->unused = 0;

    switch (indicator)
    {
      case ICMP_NET_UNREACHABLE:
           icmp_t3_hdr->icmp_code = 0;

      case ICMP_HOST_UNREACHABLE:
           icmp_t3_hdr->icmp_code = 1;

      case ICMP_PORT_UNREACHABLE:
           icmp_t3_hdr->icmp_code = 3;

      default: fprintf(stderr, "Invalid type 3 indicator\n");
    }

    /* Computes checksum for the outgoing request_packet */
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, ntohs(ip_header->ip_len) - ip_hdr_bytelen);
    ip_header->ip_sum = cksum(ip_header, ip_hdr_bytelen);

    printf("sending ICMP type 3 packet\n");
    sr_send_packet(sr, request_packet, new_packet_length, out_interface->name);
    free(request_packet);
}

/*
 * Finds the longest prefix matching with the given address.
 * Returns the ip of the the longest matching entry in the routing table.
 * A null pointer is returned if no matching entry can be found.
 */
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t addr) {

    struct sr_rt *rt_walker = sr->routing_table;

    /* The length of the match (i.e between lmatching_ip and addr) */
    int lmatching_length = 0;
    struct sr_rt *matching_entry = 0;
    int mask_length, i;
    uint32_t mask, result, entry_addr;

    while (rt_walker)
    {
        entry_addr = htonl(rt_walker->dest.s_addr);
        mask = htonl(rt_walker->mask.s_addr);

        /* Get the length of the mask */
        mask_length = 0;

        for (i = 0; i < (sizeof(uint32_t) * 8); i++)
        {
          /* In binary form, the masks's s_addr is simply a sequence of 1's followed
             by a sequence of 0's. So, simply the number of 1's must be counted
             in order to get the length of the mask
           */
          if (!(mask & (1 << ((sizeof(uint32_t) * 8) - i - 1))))
            break;
          mask_length++;
        }

        result = mask & addr;

        if ((result == (entry_addr & mask)) && (mask_length > lmatching_length))
        {
            /* The IP that rt_walker points to matches the given address, and the match
            is longer than the existing longest prefix match  */
            lmatching_length = mask_length;
            matching_entry = rt_walker;
        }

        rt_walker = rt_walker->next;
    }

    return matching_entry;
}


