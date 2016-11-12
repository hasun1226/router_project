
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "sr_if.h"
#include <string.h>

#define MAX_PORT_NUMBER 65535
#define TOTAL_WELL_KNOWN_PORTS 1024
#define DEFAULT_INTERNAL_INTERFACE "eth1"


int sr_nat_init(struct sr_nat *nat,
                time_t icmp_timeout,
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

  nat->pending_syn = NULL;
  nat->mappings = NULL;

  /* Initialize any variables here */
  nat->internal_interface_name = DEFAULT_INTERNAL_INTERFACE;
  nat->icmp_timeout = icmp_timeout;
  nat->tcp_established_timeout = tcp_established_timeout;
  nat->tcp_transmission_timeout = tcp_transmission_timeout;

  return success;
}

/*
 *  Returns 0 if there is no difference otherwise 1.
 */
int is_nat_timeout_icmp(struct sr_nat *nat, struct sr_nat_mapping *mapping)
{
    time_t now;
    time(&now);
    return difftime(now, mapping->last_updated) < nat->icmp_timeout;
}

/*
 *  Returns 0 if there is no difference otherwise 1.
 */
int is_nat_timeout_tcp(struct sr_nat *nat, struct sr_nat_connection *connection_entry)
{
    time_t now;
    time(&now);
    int et_difference = difftime(now, connection_entry->last_updated) < nat->tcp_established_timeout;
    int trans_timeout = difftime(now, connection_entry->last_updated) < nat->tcp_transmission_timeout;
    int established = connection_entry->state == tcp_state_established;
    int trasit = !established;

    return (et_difference && established) || (trans_timeout && trasit);
}

int tcp_time_out_connection(struct sr_nat *nat, struct sr_nat_connection **head)
{
    struct sr_nat_connection *current_connection = *head;

    while (current_connection != NULL)
    {

        if (is_nat_timeout_tcp(nat, current_connection))
        {
           deleteConnection(head, current_connection);
        }

        current_connection = current_connection->next;
    }

    return (*head == NULL);
}

/*
 * Delete the node n from the list of node.
 *
 * head: the head of the list.
 * n: the node to be deleted.
 */
void deleteConnection(struct sr_nat_connection **head, struct sr_nat_connection *n)
{
    /* When node to be deleted is head node*/
    if(*head == n)
    {
        /* store address of current node */
        struct sr_nat_connection *temp = *head;
        *head = temp->next;

        /* free memory */
        free(temp);

        return;
    }

    /* When it is not the first node, follow the normal deletion process*/

    /* find the previous node */
    struct sr_nat_connection *prev = *head;

    while(prev->next != NULL && prev->next != n)
    {
        prev = prev->next;
    }

    /* Check if node really exists in Linked List */
    if(prev->next == NULL)
    {
        printf("\n the given node is not in Linked List\n");
        return;
    }

    /* Remove node from Linked List */
    prev->next = prev->next->next;

    /* Free memory */
    free(n);

    return;
}

void tcp_time_out_mapping(struct sr_nat *nat, struct sr_nat_mapping **head)
{
    struct sr_nat_mapping *current_mapping = *head;

    while (current_mapping != NULL)
    {

        if ((current_mapping->type == nat_mapping_icmp && is_nat_timeout_icmp(nat, current_mapping)) ||
            (current_mapping->type == nat_mapping_tcp && tcp_time_out_connection(nat, &current_mapping->conns)))
        {
           deleteMapping(head, current_mapping);
        }

        current_mapping = current_mapping->next;
    }
}

void deleteMapping(struct sr_nat_mapping **head, struct sr_nat_mapping *n)
{
     /* When node to be deleted is head node*/
    if(*head == n)
    {
        /* store address of current node */
        struct sr_nat_mapping *temp = *head;
        *head = temp->next;

        /* free memory */
        free(temp);

        return;
    }

    /* When it is not the first node, follow the normal deletion process*/

    /* find the previous node */
    struct sr_nat_mapping *prev = *head;

    while(prev->next != NULL && prev->next != n)
    {
        prev = prev->next;
    }

    /* Check if node really exists in Linked List */
    if(prev->next == NULL)
    {
        printf("\n Given node is not present in Linked List");
        return;
    }

    /* Remove node from Linked List */
    prev->next = prev->next->next;

    /* Free memory */
    free(n);

    return;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

    struct sr_nat_mapping *current_mapping = nat->mappings;
    struct sr_nat_mapping *temp_mapping;

    while (current_mapping != NULL)
    {
        struct sr_nat_connection *current_connection = current_mapping->conns;
        struct sr_nat_connection *temp_connection;

        while(current_connection != NULL)
        {
            temp_connection = current_connection;
            current_connection = current_connection->next;
            free(temp_connection);
        }

        temp_mapping = current_mapping;
        current_mapping = current_mapping->next;
        free(temp_mapping);
    }

    /* Todo: NEED TO DELETE PENDING SYNS*/
    pthread_kill(nat->thread, SIGKILL);
    return  pthread_mutex_destroy(&(nat->lock)) &&
            pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */

    struct sr_nat *nat = (struct sr_nat *)nat_ptr;

    while (1)
    {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        /*time_t curtime = time(NULL);*/

        /* handle periodic tasks here */

        tcp_time_out_mapping(nat, &nat->mappings);

        /* Todo: NEED TO ADD TIMEOUT FOR PENDING SYNS */

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
    struct sr_nat_mapping *current_entry = nat->mappings;

    while(current_entry != NULL)
    {
        if ((current_entry->aux_ext == aux_ext) && (current_entry->type == type))
        {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, current_entry, sizeof(struct sr_nat_mapping));

            return copy;
        }

        current_entry = current_entry->next;
    }
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
    struct sr_nat_mapping *current_entry = nat->mappings;

    while(current_entry != NULL)
    {
        if ((current_entry->ip_int == ip_int) && (current_entry->aux_int == aux_int))
        {
            copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
            memcpy(copy, current_entry, sizeof(struct sr_nat_mapping));

            return copy;
        }

        current_entry = current_entry->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping *));
    /* struct sr_if *external_interface = get_external_interface(sr); */

    /* Case it is tcp mapping */
    mapping->type = type;                                     /* type */
    mapping->ip_int = ip_int;                                 /* internal ip addr */
    mapping->ip_ext = ip_ext;                                 /* external ip addr */
    mapping->aux_int = aux_int;                               /* internal port or icmp id */
    mapping->aux_ext = generate_port_number(nat->mappings, ip_int, aux_int); /* external port or icmp id */
    time(&mapping->last_updated);                             /* use to timeout mappings */
    mapping->conns = NULL;                                    /* list of connections. null for ICMP */

    mapping->next = nat->mappings;
    nat->mappings = mapping;

    struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

/*combination of private and public*/
struct sr_nat_connection *create_connection(   uint32_t dst_ip,
                                        uint16_t dst_port,
                                        uint32_t fin_sent_sequence_number,
                                        uint32_t fin_received_sequence_number)
{
    struct sr_nat_connection *new_connection = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));

    if (new_connection == NULL)
    {
        fprintf(stderr, "malloc failed to allocate a new connection\n");
        return NULL;
    }

    new_connection->dst_ip = dst_ip;
    new_connection->dst_port = dst_port;
    new_connection->fin_sent_sequence_number = fin_sent_sequence_number;
    new_connection->fin_received_sequence_number = fin_received_sequence_number;
    new_connection->state = tcp_state_established; /*DOUBLE CHECK THIS DECLARATION*/

    return new_connection;
}

/*
 * Returns a number between 1024 and MAX_PORT_NUMBER
 * mappings: the list of mappings
 * ip_int: the internal ip address,
 * aux_int: the internal port number
 */
int generate_port_number(struct sr_nat_mapping *mappings, uint32_t ip_int, uint16_t aux_int)
{
    int result = ip_int + aux_int + rand() % MAX_PORT_NUMBER;

    while (result  < TOTAL_WELL_KNOWN_PORTS || result > MAX_PORT_NUMBER || !is_unique_port_number(mappings, result))
    {
        result = ip_int + aux_int + rand() % MAX_PORT_NUMBER;
    }

    return result;
}


/*
 * Returns 1 if the port number is unique otherise 0
 * mappings: the list of mappings
 * port_number: the givent port number
 */
int is_unique_port_number(struct sr_nat_mapping *mappings, int port_number)
{
    struct sr_nat_mapping *current_mapping = mappings;

    while (current_mapping != NULL)
    {
        if (current_mapping->aux_ext == port_number){
            return 0;
        }
        current_mapping = current_mapping->next;
    }
    return 1;
}

/*
struct sr_if* get_external_interface(struct sr_instance *sr)
{
    struct sr_nat *nat = sr->nat;
    struct sr_if *internal_interface = sr_get_interface(sr, nat->internal_interface_name);
    struct sr_if *current_interface = sr->if_list;

    while(current_interface != NULL)
    {

        if (internal_interface == current_interface)
        {
          return current_interface;
        }

        current_interface = current_interface->next;
    }

    return NULL;
}
*/
