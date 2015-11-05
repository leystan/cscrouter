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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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


    sr_ethernet_hdr_t *eHeader = (sr_ethernet_hdr_t *) packet;

    uint16_t packageType = ntohs(eHeader->ether_type);

    // Drop packet if its length is not large enough for an ethernet header
    if (len < sizeof(struct sr_ethernet_hdr_t)) {
        return;
    }
    
    // Handle ARP packet
    if (packageType == ethertype_arp) {
        if (is_valid_arp_packet(packet, len)){
            handle_arp_packet(sr, packet, len, interface)
        }
    }
    // Handle IP packet
    else if (packageType == ethertype_ip) {
        if (is_valid_ip_packet(packet, len)) {
            handle_ip_packet(sr, packet, len, interface)
        }
    }
}/* end sr_ForwardPacket */

/*-----------------------------------------------------
 * Handle the ARP packet
 *-----------------------------------------------------*/
void handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet
        unsigned int len
        char* interface)
{
    struct sr_if* interface_rec;
    struct sr_arpentry *arp_entry;
    struct sr_arpreq *arp_request;

    printf("*** -> Handling ARP packet. The ARP header is:\n");
    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    interface_rec = sr_get_interface(sr, interface);

    // drop packet if interface ip does not match packet header ip
    if (interface_rec->ip != arpHeader->ar_tip){
        return;
    }

    // lookup entry in the cache
    arp_entry = sr_arpcache_lookup(&sr->cache, arpHeader->ar_sip)

    // This ARP entry already exists. The entry must be freed.
    if (arp_entry != 0) {
        free(arp_entry);
    }
    // This ARP entry does not exist
    else {
        arp_request = sr_arpcache_insert(&sr->cache, arpHeader->sr_sha, arpHeader->ar_sip);

        // send packets that are waiting on this ARP request
        if (arp_req != 0) {
            struct sr_packet *current;
            struct sr_ip_hdr *ipHeader;

            current = arp_requestrequest->packets;
            while (current != 0) {
                ipHeader = (struct sr_ip_hdr *)current->buf;
                sr_add_ethernet_header(sr,
                        current->buf,
                        current->len,
                        ipHeader->ip_dst,
                        ethertype_ip);
                current = current->next;
            }
            sr_arpreq_destroy(&sr->cache, arp_req);
        }
    }

    uint16_t opcode = ntohs(arpHeader->ar_op);

    // check if it is a request
    if (opcode == arp_op_request) {
        handle_arp_request(sr, arpHeader, interface_rec);
    }
}

/*--------------------------------------------
 * create the arp reply then send it
 *-------------------------------------------*/

void handle_arp_request(struct sr_instance *sr,
        struct sr_arp_hdr *arpHeader
        struct sr_if *interface_rec
{
    // Create a new ARP header for reply
    struct sr_arp_hdr arpHeader_reply;

    // initialize the ARP header
    arpHeader_reply.ar_hrd = htons(arp_hrd_ethernet);
    arpHeader_reply.ar_pro = htons(arp_pro_ip);
    arpHeader_reply.ar_hln = ETHER_ADDR_LEN;
    arpHeader_reply.ar_pln = sizeof(uint32_t);
    arpHeader_reply.ar_op = htons(ar_op_reply);
    memcpy(arpHeader_reply.ar_sha, interface_rec->addr, ETHER_ADDR_LEN);
    arpHeader_reply.ar_sip = interface_rec->ip;
    memcpy(arpHeader_reply.ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
    arpHeader_reply.ar_tip = arpHeader->ar_sip;

    // send the ARP header
    sr_add_ethernet_header(sr,
            (uint8_t) &arpHeader_reply,
            sizeof(struct sr_arp_hdr),
            arpHeader->ar_sip,
            htons(ethertype_arp));
}

void sr_add_ethernet_header(struct sr_instance* sr,
       uint8_t *packet;
        unsigned int len,
        uint32_t dest_ip,
        uint16_t type)
{
    struct sr_rt *entry = sr_get_longest_match(sr, dest_ip);
    
    // check if there is no entry with the longest prefix match
    if (entry == 0) {
        send_icmp(sr, packet, icmp_unreachable, icmp_port_unreachable);
        return 0;
    }
    
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, entry->gw.s_addr);
    
    if(arp_entry != 0) {
        unsigned int packet_len = len + sizeof(sr_header_hdr_t);
        uint8_t *new_packet = malloc(packet_len);
        struct sr_ethernet_hdr *eHeader = malloc(sizeof(sr_header_hdr_t));
        struct sr_if *interface_rec = sr_get_interace(sr, entry->interace);
        
        //initialize ethernet header
        eHeader->ether_type = type;
        memcpy(eHeader->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eHeader->ether_shost, interface_rec->addr, ETHER_ADDR_LEN);
        
        //initialize the new packet
        memcpy(new_packet, eHeader, sizeof(sr_ethernet_hdr_t));
        memcpy(new_packet + sizeof(sr_ethernet_hdr_t_), packet, len);
        
        sr_send_packet(sr, len + sizeof(struct sr_ethernet_hdr), entry->interface);
        
        //clean up
        free(new_packet);
        free(eHeader);
        if (arp_entry != 0) {
            free(arp_entry)
        }
        //add to the request queue
        else {
            sr_arpcache_queuereq(&sr->cache, entry->gw.s_addr, packet, len, entry->interface); 
        }
    }  
}










