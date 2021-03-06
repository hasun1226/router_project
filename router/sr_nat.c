
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_nat.h"
#include "sr_if.h"
#include "sr_utils.h"

#define MAX_PORT_NUMBER 65535
#define TOTAL_WELL_KNOWN_PORTS 1024
#define DEFAULT_INTERNAL_INTERFACE "eth1"
#define DEFAULT_EXTERNAL_INTERFACE "eth2"
#define UNSOLICITED_SYN_TIMEOUT 6

int sr_nat_init(struct sr_instance* sr,
				struct sr_nat *nat,
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

  nat->pending_syns = NULL;
  nat->mappings = NULL;

  /* Initialize any variables here */
  nat->sr = sr;
  nat->int_if_name = DEFAULT_INTERNAL_INTERFACE;
  nat->ext_if_name = DEFAULT_EXTERNAL_INTERFACE;
  nat->int_if = sr_get_interface(sr, nat->int_if_name);
  nat->ext_if = sr_get_interface(sr, nat->ext_if_name);
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
    return difftime(now, mapping->last_updated) > nat->icmp_timeout;
}

/*
 *  Returns 0 if there is no difference otherwise 1.
 */
int is_nat_timeout_tcp(struct sr_nat *nat, struct sr_nat_connection *connection_entry)
{
    time_t now;
    time(&now);
    int et_difference = difftime(now, connection_entry->last_updated) > nat->tcp_established_timeout;
    int trans_timeout = difftime(now, connection_entry->last_updated) > nat->tcp_transmission_timeout;
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

    sr_nat_pending_syn_t *current_pending_syn = nat->pending_syns;
    sr_nat_pending_syn_t *temp_pending_syn;

    while(current_pending_syn != NULL)
    {
        temp_pending_syn = current_pending_syn;
        current_pending_syn = current_pending_syn->next;
        free(temp_pending_syn);
    }

    /* Todo: NEED TO DELETE PENDING SYNS*/
    pthread_kill(nat->thread, SIGKILL);
    return  pthread_mutex_destroy(&(nat->lock)) &&
            pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */

    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
	long delay_milliseconds = 100;
	static struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = (delay_milliseconds % 1000) * 1000000;

    while (1)
    {
        nanosleep(&ts, NULL);
        pthread_mutex_lock(&(nat->lock));

        /*time_t curtime = time(NULL);*/

        /* handle periodic tasks here */

        tcp_time_out_mapping(nat, &nat->mappings);
        nat_timeout_pending_syns(nat, &nat->pending_syns);

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
			pthread_mutex_unlock(&(nat->lock));
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

            /* In case my understanding of port overloading is correct,
               there may be several internal ip-port pairs */
            /* if (type = nat_mapping_tcp) copy = copy->next;
            else */
	    pthread_mutex_unlock(&(nat->lock));
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
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

    pthread_mutex_lock(&(nat->lock));

    struct sr_if* ext = nat->ext_if;

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));

    /* Case it is tcp mapping */
    mapping->type = type;                                     /* type */

    mapping->ip_int = ip_int;                                 /* internal ip addr */

    mapping->ip_ext = ext->ip;                                /* external ip addr */

    mapping->aux_int = aux_int;                               /* internal port or icmp id */

    mapping->aux_ext = generate_port_number(nat->mappings, ip_int, aux_int);                     /* external port or icmp id (in host byte order) */

    time(&mapping->last_updated);                             /* use to timeout mappings */
    mapping->conns = NULL;                                    /* list of connections. null for ICMP */

    mapping->next = nat->mappings;
    nat->mappings = mapping;
	
	if (type == nat_mapping_tcp) {
		struct sr_nat_connection *connection = create_connection(mapping->ip_ext, mapping->aux_ext);
		connection->next = NULL;
		mapping->conns = connection;
	}

    struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

    pthread_mutex_unlock(&(nat->lock));

    return copy;
}

void nat_timeout_pending_syns(struct sr_nat *nat, sr_nat_pending_syn_t **head)
{
    sr_nat_pending_syn_t *current_pending_syn = *head;
	sr_tcp_hdr_t *tcp_hdr;

    while (current_pending_syn != NULL)
    {
		tcp_hdr = (sr_tcp_hdr_t *) (current_pending_syn->packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (is_nat_timeout_pending_syn(current_pending_syn) ||
			ntohs(tcp_hdr->dst_port) < 1024) 	/* special case */
        {
            if (sr_nat_lookup_external(nat, current_pending_syn->aux_ext, nat_mapping_tcp) == NULL)
            {
                /*TODO: FIX THIS PART OF THE FUNCTION*/    
                /*SEND ICMP UNREACHABLE*/ 
                struct sr_if *out_interface = current_pending_syn->orig_if;
				/* 
				uint8_t *packet = (uint8_t *) malloc(sizeof(sr_tcp_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
				sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
				sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
				sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				*/

                sr_send_icmp_t3(nat->sr, ICMP_PORT_UNREACHABLE, current_pending_syn->packet, (unsigned int) (current_pending_syn->packet_len), out_interface);
            }

            deletePendingSyn(head, current_pending_syn);
        }

        current_pending_syn = current_pending_syn->next;
    }
}

int is_nat_timeout_pending_syn(sr_nat_pending_syn_t *pending_syn_entry)
{
    time_t now;
    time(&now);
    int difference = difftime(now, pending_syn_entry->time_received) > UNSOLICITED_SYN_TIMEOUT;

    return difference;
}

void deletePendingSyn(sr_nat_pending_syn_t **head, sr_nat_pending_syn_t *n)
{
    /* When node to be deleted is head node*/
    if(*head == n)
    {
        /* store address of current node */
        sr_nat_pending_syn_t *temp = *head;
        *head = temp->next;

        /*free the ip header*/
        free(temp->ip_hdr);
		
		/* free the stored packet */
		free(temp->packet);

        /* free memory */
        free(temp);

        return;
    }

    /* When it is not the first node, follow the normal deletion process*/

    /* find the previous node */
    sr_nat_pending_syn_t *prev = *head;

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

    /*Free the ip header*/
    free(n->ip_hdr);
    /* Free memory */
    free(n);


    return;
}

void sr_nat_insert_pending_syn(struct sr_nat *nat, uint16_t aux_ext, uint8_t *packet, uint32_t len, struct sr_if *orig_if) 
{
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	
  unsigned int ip_len = ntohs(ip_header->ip_len);
  sr_nat_pending_syn_t *pending_syn = (sr_nat_pending_syn_t *)malloc(sizeof(sr_nat_pending_syn_t));
  time(&pending_syn->time_received);
  pending_syn->aux_ext = aux_ext;
  pending_syn->ip_hdr = malloc(ip_len);
  memcpy(pending_syn->ip_hdr,ip_header,ip_len);
  pending_syn->packet = malloc(len);
  memcpy(pending_syn->packet, packet, len);
  pending_syn->packet_len = len;
  pending_syn->orig_if = orig_if;

  pending_syn->next = nat->pending_syns;
  nat->pending_syns = pending_syn;
}

/*combination of private and public*/
struct sr_nat_connection *create_connection(uint32_t dst_ip, uint16_t dst_port)
{
    struct sr_nat_connection *new_connection = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));

    if (new_connection == NULL)
    {
        fprintf(stderr, "malloc failed to allocate a new connection\n");
        return NULL;
    }

    new_connection->dst_ip = dst_ip;
    new_connection->dst_port = dst_port;
    new_connection->fin_sent_sequence_number = 0;
    new_connection->fin_received_sequence_number = 0;
    new_connection->state = 0; /*DOUBLE CHECK THIS DECLARATION*/
	time(&new_connection->last_updated);

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

    int divisor = RAND_MAX/(MAX_PORT_NUMBER+1);
    int result;

    do { 
        result = rand() / divisor;
    } while (result > MAX_PORT_NUMBER || result < TOTAL_WELL_KNOWN_PORTS || !is_unique_port_number(mappings, result));

    printf("final Port number: %d\n", result);
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

void update_tcp_connection(struct sr_nat_mapping *mappings, uint32_t dst_ip, uint16_t dst_port,
                            sr_tcp_hdr_t *tcp_header, int incoming)
{
    assert(mappings->type == nat_mapping_tcp);

    /* Update timestamp for entire mapping */
    time(&(mappings->last_updated));

    struct sr_nat_connection *connection = contains_connection(mappings->conns, dst_ip, dst_port);

    if (connection != NULL)
    {
        time(&connection->last_updated);

        if (incoming) 
        {
             update_incoming_tcp_state(connection, tcp_header);
        } 

        else if(!incoming)
        {
            update_outgoing_tcp_state(connection, tcp_header);
        } 
    }

    if (connection == NULL) 
    {
        /* create new tcp connection */
        connection = create_connection(dst_ip, dst_port);
        connection->next = mappings->conns;
        mappings->conns = connection;

        /* initialize connection state */
        if (incoming)
        {
            init_incoming_tcp_state(connection, tcp_header);
        }
            
        else if(!incoming)
        {
            init_outgoing_tcp_state(connection, tcp_header);
        }  
    }

    time(&connection->last_updated);
}

/* 
 * Returns the entry of the given connection otherwise null
 *
 */
struct sr_nat_connection *contains_connection(struct sr_nat_connection *connections, uint32_t dst_ip, uint16_t dst_port)
{
    struct sr_nat_connection *current_connection = connections;

    while(current_connection != NULL)
    {  
        if ((dst_ip == current_connection->dst_ip) && (dst_port == current_connection->dst_port)) 
        {
            return current_connection;
        }
        current_connection = current_connection->next;
    }
    
    return NULL;
}

void update_outgoing_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header)
{
    uint32_t sequence_number = ntohl(tcp_header->seq);

    if((tcp_header->flag & RST) == RST)
    {
        connection->state = tcp_state_closed;
    }

    sr_nat_tcp_state current_state = connection->state;

    switch (current_state)
    {
        case tcp_state_closed: 
            
            if((tcp_header->flag & SYN) == SYN)
            {
                init_outgoing_tcp_state(connection, tcp_header);
            }
            break;
    
        case tcp_state_syn_received_processing:
            
            if ((tcp_header->flag & SYN) == SYN && (tcp_header->flag & ACK) == ACK) 
            {
                connection->state = tcp_state_syn_received;
            }
            break;

        case tcp_state_established:
            
            if((tcp_header->flag & FIN) == FIN)
            {
                connection->state = tcp_state_fin_wait_1;
                connection->fin_sent_sequence_number = sequence_number;
            }
            
            if((tcp_header->flag & SYN) == SYN)
            {
                init_outgoing_tcp_state(connection, tcp_header);
            }
            break;

        case tcp_state_close_wait:
            
            if ((tcp_header->flag & FIN) == FIN) 
            {
                connection->state = tcp_state_last_ack;
                connection->fin_sent_sequence_number = sequence_number;
            } 

            if ((tcp_header->flag & SYN) == SYN) {
                init_outgoing_tcp_state(connection, tcp_header);
            }
            break;
    
        case tcp_state_last_ack:
            if ((tcp_header->flag & SYN) == SYN) 
            {
                init_outgoing_tcp_state(connection, tcp_header); 
            }
            break;

        case tcp_state_time_wait:
            
            if ((tcp_header->flag & SYN) == SYN) 
            {
                init_outgoing_tcp_state(connection, tcp_header); 
            }
            break;

        default:
            break;
    } 
}

void init_incoming_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header) 
{

    if ((tcp_header->flag & SYN) == SYN) 
    {
        connection->state = tcp_state_syn_received_processing;
        connection->fin_sent_sequence_number = 0;
        connection->fin_received_sequence_number = 0;
    } 

    else 
    {
        /* connection reset */
        connection->state = tcp_state_closed;
    }
}
void update_incoming_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header)
{
    uint32_t sequence_number = ntohl(tcp_header->seq);
    uint32_t acknowledge_number = ntohl(tcp_header->ack);

    if((tcp_header->flag & RST) == RST)
    {
        connection->state = tcp_state_closed;
    }

    sr_nat_tcp_state current_state = connection->state;

    switch (current_state)
    {
        case tcp_state_closed: 
            
            if((tcp_header->flag & SYN) == SYN)
            {
                init_incoming_tcp_state(connection, tcp_header);
            }
            break;

        case tcp_state_syn_sent:
            
            if ((tcp_header->flag & SYN) == SYN) 
            {
                
                /* when SYN was received */
                if ((tcp_header->flag & ACK) == ACK) {
                    /* SYN+ACK */
                    connection->state = tcp_state_established;
                } 

                else 
                {
                    /* simultaneous open */
                    connection->state = tcp_state_syn_received;
                }
                break;
            }

        case tcp_state_syn_received:
            
            if ((tcp_header->flag & ACK) == ACK) 
            {
                /* SYN+ACK */
                connection->state = tcp_state_established;
            }
            break; 

        case tcp_state_established:
            
            if((tcp_header->flag & FIN) == FIN)
            {
                connection->state = tcp_state_close_wait;
                connection->fin_received_sequence_number = sequence_number;
            }
            
            if((tcp_header->flag & SYN) == SYN)
            {
                init_incoming_tcp_state(connection, tcp_header);
            }
            break;

        case tcp_state_close_wait:
            
            if ((tcp_header->flag & FIN) == FIN) 
            {
                connection->state = tcp_state_last_ack;
                connection->fin_sent_sequence_number = sequence_number;
            } 

            if ((tcp_header->flag & SYN) == SYN) {
                init_outgoing_tcp_state(connection, tcp_header);
            }
            break;
    
        case tcp_state_fin_wait_1:

            /* FIN or FIN+ACK */
            if ((tcp_header->flag & FIN) == FIN) 
            {
                connection->state = tcp_state_time_wait;
                connection->fin_received_sequence_number = sequence_number;
            }

            if ((tcp_header->flag & ACK) == ACK && (acknowledge_number > connection->fin_sent_sequence_number)) 
            {  
                /* FIN */
                connection->state = tcp_state_fin_wait_2;
            } 

            if ((tcp_header->flag & SYN) == SYN) 
            {
                /* Reset connection */
                init_incoming_tcp_state(connection, tcp_header); 
            }
            break;

        case tcp_state_fin_wait_2:
            
            if ((tcp_header->flag & FIN) == FIN) 
            {
                connection->state = tcp_state_time_wait;
                connection->fin_received_sequence_number = sequence_number; 
            }

            if ((tcp_header->flag & SYN) == SYN) 
            {
                /* Reset connection */
                init_incoming_tcp_state(connection, tcp_header); 
            }
            break;

        default:
            break;
    } 
}

void init_outgoing_tcp_state(struct sr_nat_connection *connection, sr_tcp_hdr_t *tcp_header) 
{

    if ((tcp_header->flag & SYN) == SYN) 
    {
        connection->state = tcp_state_syn_sent;
        connection->fin_sent_sequence_number = 0;
        connection->fin_received_sequence_number = 0;
    } 
    else 
    {
        /* connection reset */
        connection->state = tcp_state_closed;
    }
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
