
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_if.h"

typedef enum {
    tcp_state_listen,
    tcp_state_syn_sent,
    tcp_state_syn_received_processing,
    tcp_state_syn_received,
    tcp_state_established,
    tcp_state_fin_wait_1,
    tcp_state_fin_wait_2,
    tcp_state_close_wait,
    tcp_state_closing,
    tcp_state_last_ack,
    tcp_state_time_wait,
    tcp_state_closed
} sr_nat_tcp_state;

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_pending_syn
{
  /* add TCP connection state data members here */
  time_t time_received;
  uint16_t aux_ext;
  sr_ip_hdr_t *ip_hdr;
  struct sr_nat_pending_syn *next;
};
typedef struct sr_nat_pending_syn sr_nat_pending_syn_t;

struct sr_nat_connection {
  /* add TCP connection state data members here */
    uint32_t dst_ip;
    uint16_t dst_port;
    uint32_t fin_sent_sequence_number;
    uint32_t fin_received_sequence_number;
    sr_nat_tcp_state state;
    time_t last_updated;
    struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  sr_nat_pending_syn_t *pending_syn;
  char *internal_interface_name;
  struct sr_if *ext_if;

   /*Timeout*/
  time_t icmp_timeout;
  time_t tcp_established_timeout;
  time_t tcp_transmission_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};



struct sr_nat_connection *create_connection(uint32_t dst_ip, uint16_t dst_port);
struct sr_nat_connection *contains_connection(struct sr_nat_connection *connections, uint32_t dst_ip, uint16_t dst_port);
/* struct sr_if *get_external_interface(struct sr_instance *sr); */
int tcp_time_out_connection(struct sr_nat *nat, struct sr_nat_connection **head);
void deleteConnection(struct sr_nat_connection **head, struct sr_nat_connection *n);
int is_nat_timeout_tcp(struct sr_nat *nat, struct sr_nat_connection *connection_entry);
int is_nat_timeout_icmp(struct sr_nat *nat, struct sr_nat_mapping *mapping);
int generate_port_number(struct sr_nat_mapping *mappings, uint32_t ip_int, uint16_t aux_int);
int is_unique_port_number(struct sr_nat_mapping *mappings, int port_number);

void tcp_time_out_mapping(struct sr_nat *nat, struct sr_nat_mapping **head);

void update_tcp_connection(struct sr_nat_mapping *mappings, uint32_t dst_ip, uint16_t dst_port,
                            sr_tcp_hdr_t *tcp_header, int incoming);

void init_outgoing_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header);
void update_outgoing_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header);

void init_incoming_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header);
void update_incoming_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header);

void deleteMapping(struct sr_nat_mapping **head, struct sr_nat_mapping *n);

int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);


#endif
