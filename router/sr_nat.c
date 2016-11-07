
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

#define MAX_PORT_NUMBER 65535
#define TOTAL_WELL_KNOWN_PORTS 1024

sr_nat_connection *create_connection(   uint32_t dst_ip, 
                                        uint16_t dst_port, 
                                        uint32_t fin_sent_sequence_number, 
                                        uint32_t fin_received_sequence_number); 

int sr_nat_init(struct sr_nat *nat, 
                time_t icmp_query_timeout,
                time_t tcp_established_timeout,
                time_t tcp_transmission_timeout) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  nat->icmp_query_timeout = icmp_query_timeout;
  nat->tcp_established_timeout = tcp_established_timeout;
  nat->tcp_transmission_timeout = tcp_transmission_timeout;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = (sr_nat_mapping *)malloc(sizeof(sr_nat_mapping));
    
  /*Case it is tcp mapping*/
  mapping->ip_int = ip_int /* internal ip addr */
  mapping->ip_ext = /* external ip addr */
  mapping->aux_int = aux_int/* internal port or icmp id */
  mapping->aux_ext = generate_port_number(ip_int, aux_int); /* external port or icmp id */
  time(&mapping->last_updated); /* use to timeout mappings */
  mapping->conns = NULL; /* list of connections. null for ICMP */
  mapping->next = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

/*combination of private and public*/
sr_nat_connection *create_connection(   uint32_t dst_ip, 
                                        uint16_t dst_port, 
                                        uint32_t fin_sent_sequence_number, 
                                        uint32_t fin_received_sequence_number)
{
    sr_nat_connection *new_connection = malloc(sizeof(sr_nat_connection));

    if (new_connection == NULL)
    {
        fprintf(stderr, "malloc failed to allocate a new connection\n");
        return;
    }

    new_connection->dst_ip = dst_ip;
    new_connection->dst_port = dst_port; 
    new_connection->fin_sent_sequence_number = fin_sent_sequence_number;
    new_connection->fin_received_sequence_number = fin_received_sequence_number;
    new_connection->state = tcp_state_established; /*DOUBLE CHECK THIS DECLARATION*/

    return new_connection;
}

/*
 * Returns a number
 * ip_int: the internal ip address,  
 * aux_int: the internal port number
 */
int generate_port_number(uint32_t ip_int, uint16_t aux_int)
{
    int result;

    while ((result = ip_int + aux_int + rand() % MAX_PORT_NUMBER) < TOTAL_WELL_KNOWN_PORTS)
    {
        return result;
    }

    return result;
}
