/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 *
 **********************************************************************/
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include <pthread.h>
#include <sys/time.h>
#define ETHERNET_ARP 0x806
#define ETHERNET_IP 0x800
#define ETHERNET_ICMP 0x01
#define ETHERNET_TCP 0x06
#define ETHERNET_UDP 0x11
#define ETHERNET_ARP_REQUEST 1
#define ETHERNET_ARP_RESPONSE 2
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_RESPONSE 0
#define ETHER_ADDR_LEN 6
#define ETHER_ADDR_HDR 14
#define ICMP_HDR 34
#define ARP_HDR  28
#define TRUE 1
#define FALSE 0
#define DESTINATION UNREACHABLE 3
#define HOST UNREACHABLE 12
#define HOP_COUNT 1
#define ARP_HT 1
#define IP_LEN 4
#define THA 0x00;
#define BHA 0xFF;

	

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/
struct arp_cache* ac_head;
struct packet_buffer* phead;
pthread_t arpcleanup;
pthread_mutex_t resloc;

void arp_request(struct sr_instance*,struct sr_arphdr*,struct sr_ethernet_hdr*,
        uint8_t*,unsigned int,
        char* interface);
void icmp_request(struct sr_instance*,struct sr_ethernet_hdr*,struct ip*,struct sr_icmphdr*,
                 uint8_t*,unsigned int,char*);
char* check_routing_table(uint32_t,struct sr_instance*,struct sr_ethernet_hdr*,char*,uint32_t*);
void packet_forward(struct sr_instance*,struct sr_ethernet_hdr*,struct ip*,
					uint8_t*,unsigned int,char*);
int Check_Router_Address(uint32_t,struct sr_instance*);
unsigned char* Retrieve_Interface_Address(char*,struct sr_instance*);
uint32_t Retrieve_IP_Address(char*,struct sr_instance*);
void arpcache_update(uint32_t,uint8_t*);
void RetrieveFromArpcache(uint32_t ipaddr,uint8_t*);
void PacketBufferInsertion(uint8_t*,unsigned int,struct ip*);
int ArpCacheLookup(uint32_t);
void PrintEntriesInArpCache();
void CreateARPRequest(struct sr_instance*,struct ip*,
						char*,unsigned char*,uint32_t,uint32_t);
uint16_t ip_sum_calc(uint16_t, uint8_t*);				
void PacketProcessing(struct sr_instance*,struct sr_ethernet_hdr*,uint32_t,char*);
void PortUnreachable(struct sr_instance*,struct sr_ethernet_hdr*,
					struct ip*,uint8_t*,unsigned int,char*,int,int);
void arpcache_deletion();
void PacketBufferDeletion(int);
int LongestMask(uint32_t);
void *cleanup(void*);
int TimeDiff(struct timeval);

void *cleanup(void* a)
{
	while(TRUE)
	{
		printf("Arpcache deletion");
		sleep(15);
		arpcache_deletion();
		PrintEntriesInArpCache();
	}
}

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    ac_head = NULL;
    phead = NULL;
    pthread_mutex_init(&resloc,NULL);
    pthread_create(&arpcleanup,NULL,&cleanup,NULL);
    
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
    uint8_t* pck_buf = (uint8_t*)malloc(len);
	memcpy(pck_buf,packet,len);
	//printf("*** -> Received packet of length %d \n",len);
	//for(int i=0;i<len;i++) printf("\nByte %d = %x",i,*(pck_buf+i));
	struct sr_ethernet_hdr *eh_pkt; //ethernet header
    struct sr_arphdr* arp_pkt; //arp packet header
    struct sr_icmphdr* icmp_pkt; //icmp packet header
    struct ip* ip_pkt;
    ip_pkt = (struct ip*)malloc(sizeof(struct ip));
    icmp_pkt = (struct sr_icmphdr*)malloc(sizeof(struct sr_icmphdr));
    eh_pkt = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
    //struct packet_buffer* pb; // Packet Buffer created
    //pb = (struct packet_buffer*)malloc(sizeof(struct packet_buffer));
    memcpy(eh_pkt,pck_buf,sizeof(struct sr_ethernet_hdr)); 
    arp_pkt = (struct sr_arphdr*)malloc(sizeof(struct sr_arphdr));
    uint16_t val = ntohs(eh_pkt->ether_type);
    //printf("\n The ether type of the packet is %x \n",val);
    if(val == ETHERNET_ARP)
    {
	 //printf(" \n Entering Ethernet_ARP \n");
     memcpy(arp_pkt,&pck_buf[sizeof(struct sr_ethernet_hdr)],sizeof(struct sr_arphdr));
	 //printf(" \n The size of arp packet is %lu \n",sizeof(arp_pkt));
     // ARP packet
     if(ntohs(arp_pkt->ar_op)== ETHERNET_ARP_REQUEST) 
     {
        //printf("\n ARP Req recd. %x \n",ntohl(arp_pkt->ar_tip));
        arp_request(sr,arp_pkt,eh_pkt,pck_buf,len,interface);// arp_request function gets called
	 }
	 else if(ntohs(arp_pkt->ar_op)== ETHERNET_ARP_RESPONSE)
	 {
		 //printf("\n The IP address of the incoming package %x \n",ntohl(arp_pkt->ar_tip));
		 arpcache_update(arp_pkt->ar_sip,arp_pkt->ar_sha);
		 PrintEntriesInArpCache();
		 //arpcache_deletion(arp_pkt->ar_sip);//check for deletion
		 //PrintEntriesInArpCache();
		 //printf("Entered the values into Arp cache and have already inserted the packet in packet buffer");
		 PacketProcessing(sr,eh_pkt,arp_pkt->ar_sip,interface); // processing the packets
		 
     }
	}
    else if(ntohs(eh_pkt->ether_type) == ETHERNET_IP)
    {
	 //printf(" \n Entering IP layer! The ether type is %x \n",val);
	 memcpy(ip_pkt,&pck_buf[sizeof(struct sr_ethernet_hdr)],sizeof(struct ip));
	 arpcache_update(ntohl(ip_pkt->ip_src.s_addr),eh_pkt->ether_shost);
	 if(ip_pkt->ip_p == ETHERNET_ICMP)
	 {
		 //printf("\n Hurray !! Entered ICMP The ip_p protocol value is %x \n",ip_pkt->ip_p);
    	 //int icmp_pkt_len = len - sizeof(struct ip) - sizeof(struct sr_icmphdr);
		 //printf("\n The icmp_pkt length is %d \n",icmp_pkt_len);
		 memcpy(icmp_pkt,pck_buf+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip),sizeof(struct sr_icmphdr));
		 int myIf = Check_Router_Address(ip_pkt->ip_dst.s_addr,sr);
		 //printf("\n My IF check value is %d \n",myIf);
		 //uint16_t calc_checksum_ip = (ip_sum_calc(sizeof(struct ip),(uint8_t*)ip_pkt));
		 //printf("The calculated IP Checksum of the forwarding packet is %x",calc_checksum_ip);
		 if((icmp_pkt->type == ICMP_ECHO_REQUEST) && (myIf == 0))
		 {
			 //printf("\n Hurray !! Entered It is my destination address is %x \n",icmp_pkt->type);
	         icmp_request(sr,eh_pkt,ip_pkt,icmp_pkt,pck_buf,len,interface);
		 }
		 else if((myIf != 0) && (icmp_pkt->type == ICMP_ECHO_REQUEST))
		 {
			// Packet Forwarding It is :) 
			//printf(" \n Oops!! It is packet forwarding time !! \n");
			packet_forward(sr,eh_pkt,ip_pkt,pck_buf,len,interface);
		 }
		 else if((myIf != 0) && (icmp_pkt->type == ICMP_ECHO_RESPONSE))
		 {
			 packet_forward(sr,eh_pkt,ip_pkt,pck_buf,len,interface);
		 }
	 }
	 else if(ip_pkt->ip_p == ETHERNET_TCP)
	 {
		 //printf("TCP Protocol it is");
		 int myIf = Check_Router_Address(ip_pkt->ip_dst.s_addr,sr);
		 if(myIf == 0)
		 {
			 //printf("Oops!! Pinged the wrong IP Address!! You are gonna receive Port Unreachable");
			 PortUnreachable(sr,eh_pkt,ip_pkt,pck_buf,len,interface,3,3);
			 
		 }
		 else if(myIf != 0)
		 {
			packet_forward(sr,eh_pkt,ip_pkt,pck_buf,len,interface);
		 }
	 }
	 else if(ip_pkt->ip_p == ETHERNET_UDP)
	 {
		 //printf("Reached UDP Protocol");
		 int myIf = Check_Router_Address(ip_pkt->ip_dst.s_addr,sr);
		 if(myIf == 0)
		 {
			 //printf("Oops!! Pinged the wrong IP Address!! You are gonna receive Port Unreachable");
			 PortUnreachable(sr,eh_pkt,ip_pkt,pck_buf,len,interface,3,3);
		 }
		 else if(myIf != 0)
		 {
			if(ip_pkt->ip_ttl == 1)
			{
				//printf("Oops!! Time to live is expired!!************");
				PortUnreachable(sr,eh_pkt,ip_pkt,pck_buf,len,interface,11,0);
			}
			else
			{
				//printf("Hi.. you have reached UDP Protocol's packet forward");
				packet_forward(sr,eh_pkt,ip_pkt,pck_buf,len,interface);
			}
		 }
	 }
   }
}

void packet_forward(struct sr_instance* sr,struct sr_ethernet_hdr* eh_pkt,struct ip* ip_pkt1,
					uint8_t* packet,unsigned int len,char* interface)
{
	//printf("Packet forwarding!!");
	char ifname[sr_IFACE_NAMELEN]; // through which forwarding is done
	int checksum = ntohs(ip_pkt1->ip_sum);
	ip_pkt1->ip_sum = 0;
	uint8_t* hw = (uint8_t*)malloc(ETHER_ADDR_LEN);
	//sr->arp_cc = NULL;
	//uint8_t* pkt1 = (uint8_t*)malloc(len);
    uint16_t calc_checksum_ip = (ip_sum_calc(sizeof(struct ip),(uint8_t*)ip_pkt1));
    uint32_t* nexthop=(uint32_t*)malloc(sizeof(uint32_t));
	//printf("The calculated IP Checksum of the forwarding packet is %d",calc_checksum_ip);
	if(calc_checksum_ip != checksum)
    {
	   printf("\n Checksum error. The calculated checksum does not match with the packet's checksum which is %d",checksum);
    }
	//check in the routing table.
	//printf("\n Going to check the if name and the next hop address \n");
	char* if1 = check_routing_table(ip_pkt1->ip_dst.s_addr,sr,eh_pkt,ifname,nexthop);
	memcpy(ifname,if1,sr_IFACE_NAMELEN);
	unsigned char* ifhw1 = Retrieve_Interface_Address(ifname,sr);
	uint32_t ifip = Retrieve_IP_Address(ifname,sr);
	memcpy(eh_pkt->ether_shost,ifhw1,ETHER_ADDR_LEN);
	//constructing IP Packet
	ip_pkt1->ip_ttl=ip_pkt1->ip_ttl-1;
	//printf("\n The current ttl count is %x \n",ip_pkt1->ip_ttl);
	ip_pkt1->ip_sum = htons(ip_sum_calc(sizeof(struct ip),(uint8_t*)ip_pkt1));
	uint16_t check = ip_pkt1->ip_sum;
	//printf("\n The calculated IP Checksum of the forwarding packet is %d \n",check);
	arpcache_update(ip_pkt1->ip_src.s_addr,eh_pkt->ether_shost);
	//If destination address present in arpcache, send the packet accordingly.
	PrintEntriesInArpCache();
    if(ArpCacheLookup(ip_pkt1->ip_dst.s_addr) == 0) 
	{
		memcpy(eh_pkt->ether_shost,ifhw1,ETHER_ADDR_LEN);
		memcpy(packet,eh_pkt,sizeof(struct sr_ethernet_hdr));
		memcpy(packet+sizeof(struct sr_ethernet_hdr),ip_pkt1,sizeof(struct ip));
		//printf("Not present in the cache");
		PacketBufferInsertion(packet,len,ip_pkt1);
		//printf("invoking arp request function");
		CreateARPRequest(sr,ip_pkt1,ifname,ifhw1,ifip,*nexthop);
	}
	else 
	{
			 //printf("Hurray I have received ICMP Echo Response!!");
			 RetrieveFromArpcache(ntohl(ip_pkt1->ip_dst.s_addr),hw);
			 struct sr_ethernet_hdr* eh = eh_pkt;
			 memcpy(eh->ether_shost,ifhw1,ETHER_ADDR_LEN);
			 memcpy(eh->ether_dhost,hw,ETHER_ADDR_LEN);
			 memcpy(packet,eh,sizeof(struct sr_ethernet_hdr));
			 sr_send_packet(sr,packet,len,ifname);
	 }
}


void CreateARPRequest(struct sr_instance* sr,struct ip* ip_pkt1,
						char* ifname,unsigned char* ifhw1,uint32_t ifip,uint32_t nexthop)
{
	struct sr_ethernet_hdr* eh;
	eh = malloc(sizeof(struct sr_ethernet_hdr));
	//struct ip* ip_pkt = ip_pkt1;
	struct sr_arphdr* arp_pkt;
	arp_pkt = malloc(sizeof(struct sr_arphdr));
	int len = sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_arphdr);
	uint8_t* packet;
	packet = malloc(len);
	memcpy(eh->ether_shost,ifhw1,ETHER_ADDR_LEN);
	eh->ether_type = htons(ETHERNET_ARP);
	memcpy(arp_pkt->ar_sha,ifhw1,ETHER_ADDR_LEN);
	arp_pkt->ar_sip = ifip;
	for(int i = 0;i<ETHER_ADDR_LEN;i++)
	{
		*((arp_pkt->ar_tha)+i) = THA;
		*((eh->ether_dhost)+i) = BHA;
	}
	arp_pkt->ar_tip = nexthop;
	arp_pkt->ar_hrd = htons(ARPHDR_ETHER);
	arp_pkt->ar_hln = 6;
	arp_pkt->ar_op = htons(ARP_REQUEST);
	arp_pkt->ar_pln = 4;
	arp_pkt->ar_pro = htons(ETHERNET_IP); 
	memcpy(packet,eh,ETHER_ADDR_HDR);
	memcpy(packet+sizeof(struct sr_ethernet_hdr),arp_pkt,ARP_HDR);
	//for(int i=0;i<len;i++) printf("\nByte %d = %x",i,*(packet+i));
	//printf("sending the arp request");
	sr_send_packet(sr,packet,len,ifname);
}

char* check_routing_table(uint32_t ip_dst,struct sr_instance* sr,struct sr_ethernet_hdr* eh_pkt,char* ifname,uint32_t* nextHopIp)
{
	//printf("Entering the routing table %x",ip_dst);
	struct sr_rt* rt1 = sr->routing_table;
	int maxlength = 0;
	int Length = 0;
	while(rt1)
	{
		//printf("Loop!!");
		Length = LongestMask(rt1->mask.s_addr);
		if(((ip_dst & rt1->mask.s_addr) == (rt1->dest.s_addr & rt1->mask.s_addr)) && (Length >= maxlength))
		{
			//printf("Loop2 %x",ip_dst);
			maxlength = Length;
			*nextHopIp = rt1->gw.s_addr;
			memcpy(ifname,rt1->interface,sr_IFACE_NAMELEN); 
		}
		rt1 = rt1->next;
	}
	return ifname;
}

int LongestMask(uint32_t m)
{
	int l = 0;
	while(m > 0)
	{
		l++;
		m=m<<1;
	}
	return l;
}
			
			


// check for whether the destination address is one of the router's addresses
int Check_Router_Address(uint32_t x,struct sr_instance* sr)
{
	struct sr_if* if1 = sr->if_list;
	while(if1)
	{
		if(if1->ip == x)
		{
			return 0;							
  	    }
  	    if1=if1->next;
    }
    return 1;
}

// Retrieving Interface address
unsigned char* Retrieve_Interface_Address(char* iface1,struct sr_instance* sr)
{
	//printf("\n Hurray!! I am gonna retrieve Interface Address%s \n",iface1);
	struct sr_if* if2 = (struct sr_if*)sr->if_list;
	unsigned char* sha;
	while(if2)
	{
		if((strcmp(if2->name,iface1)) == 0)
		{
			//printf(" \n The hardware address is %x \n",*(if2->addr));
			sha = if2->addr;
			break;
		}
		if2 = if2->next;
	}
	return sha;
}

// Retrieve IP address
uint32_t Retrieve_IP_Address(char* iface1,struct sr_instance* sr)
{
	//printf("\n Hurray!! I am gonna retrieve IP Address%s \n",iface1);
	struct sr_if* if2 = (struct sr_if*)sr->if_list;
	uint32_t sha;
	while(if2)
	{
		if((strcmp(if2->name,iface1)) == 0)
		{
			//printf(" \n The hardware address is %x \n",*(if2->addr));
			sha = if2->ip;
			break;
		}
		if2 = if2->next;
	}
	return sha;
	//printf("The incoming interface %s and the router's interface are %s \n",iface1,if2->name);
}

	 
//ARP request function
void arp_request(struct sr_instance* sr,struct sr_arphdr* x,struct sr_ethernet_hdr* eh,uint8_t *packet,
                 unsigned int len,  char* interface)
{
			printf("\n /*........Ethernet ARP Request.......*/ %x",x->ar_tip);
  	        unsigned char *shost_addr;
  	        // Check if the destination address is one of the interfaces
  	        if(Check_Router_Address(x->ar_tip,sr) == 0)
  	        {
				//printf("\n Hurray!! It is one of my interfaces !! %x \n",x->ar_tip);
				shost_addr = Retrieve_Interface_Address(interface,sr);
				//printf("The host address is %s",shost_addr);
			}
  	        struct sr_ethernet_hdr* eth_rsp;
	        eth_rsp = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
            // creating the ethernet packet
            eth_rsp->ether_type= htons(ETHERNET_ARP);
            memcpy(eth_rsp->ether_shost,shost_addr,ETHER_ADDR_LEN);
            memcpy(eth_rsp->ether_dhost, x->ar_sha, ETHER_ADDR_LEN);
            // storing the ethernet packet in the main packet
            memcpy(packet, eth_rsp, sizeof(struct sr_ethernet_hdr));
            // creating the arp packet
            x->ar_op=htons(ETHERNET_ARP_RESPONSE);
            memcpy(x->ar_sha,shost_addr, ETHER_ADDR_LEN);
            memcpy(x->ar_tha, eth_rsp->ether_dhost, ETHER_ADDR_LEN);
            uint32_t temp;
            temp = x->ar_tip;
            x->ar_tip=(x->ar_sip);
            x->ar_sip = temp;
            //x->ar_sip=(sr->if_list->ip); 
            // storing the arp packet in the main packet
            memcpy(&packet[sizeof(struct sr_ethernet_hdr)], x, sizeof(struct sr_arphdr));
            sr_send_packet(sr,packet,len,interface);
}
//icmp request function
void icmp_request(struct sr_instance* sr,struct sr_ethernet_hdr* eh,struct ip* ipp,struct sr_icmphdr* ih,
                 uint8_t *packet,unsigned int len,  char* interface)
{
			printf("\n /*........Ethernet ICMP Request....................................*/");
			//printf("\n The interface is %s",interface);
			PrintEntriesInArpCache();
			unsigned char *shost_addr;
			uint32_t shost_ip;
			if((Check_Router_Address(ipp->ip_dst.s_addr,sr)) == 0)
  	        {
				//printf("Hurray!! It is one of my interfaces !! %x",ipp->ip_dst.s_addr);
				shost_addr = Retrieve_Interface_Address(interface,sr);
				shost_ip = Retrieve_IP_Address(interface,sr);
				//printf("Host is %-.8X",shost_ip);
			}
			
			// check the check sum value.
			uint16_t checksum = ntohs(ipp->ip_sum);
			//printf(" \n The checksum is %x \n ",checksum);
			ipp->ip_sum = 0;
			uint16_t calc_checksum_ip = (ip_sum_calc(sizeof(struct ip),(uint8_t*)ipp));
			//printf(" \n The calculated checksum is %x \n",calc_checksum_ip);
     		if((ip_sum_calc(sizeof(struct ip),(uint8_t*)ipp)) != checksum)
     		{
				printf("\n Checksum error. The calculated checksum does not match with the packet's checksum which is %d",checksum);
    		}
    		//printf("\n Hurray !! Checksum Matches for IP %x \n",calc_checksum_ip);
    		//copying the ethernet packet to the appropriate entry
			eh->ether_type= htons(ETHERNET_IP);
			memcpy(eh->ether_dhost, eh->ether_shost, ETHER_ADDR_LEN);
            memcpy(eh->ether_shost, shost_addr, ETHER_ADDR_LEN);
            memcpy(packet,eh,sizeof(struct sr_ethernet_hdr));//restructuring ethernet packet in main packet
            // copying the ip packet to the appropriate entry
            uint32_t t1 = ipp->ip_src.s_addr;
			ipp->ip_src.s_addr = shost_ip;	//ipp->ip_dst.s_addr;
            ipp->ip_dst.s_addr = t1;
            ipp->ip_ttl = 0xFF;
            ipp->ip_sum = htons(ip_sum_calc(sizeof(struct ip),(uint8_t*)ipp));
            //printf("\n The calculated IP_Checksum after modifications is %x \n",ipp->ip_sum);
            memcpy(packet+sizeof(struct sr_ethernet_hdr),ipp,sizeof(struct ip));//restructuring the ip packet in main packet
            //copying the icmp packet to the appropriate entry
            int icmp_data_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip) - sizeof(struct sr_icmphdr);
            int icmp_buf_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
            int icmp_ip_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct sr_icmphdr);
            uint8_t* icmp_buf = malloc(icmp_buf_len);
            uint16_t icmp_checksum = ntohs(ih->checksum);
			//ih->checksum = 0;
			memcpy(icmp_buf,ih,sizeof(struct sr_icmphdr));
			memcpy(icmp_buf+sizeof(struct sr_icmphdr),packet+icmp_ip_len,icmp_data_len);
			//printf("\n The ICMP_Checksum of the received packet is %x \n",icmp_checksum);
			uint16_t calc_icmp_cs = (ip_sum_calc(icmp_buf_len,(uint8_t*)icmp_buf));
			//printf(" \n The calculated ICMP_Checksum of the received packet is %x \n",calc_icmp_cs);
			if(!(ip_sum_calc(icmp_buf_len,(uint8_t*)icmp_buf)) == icmp_checksum)
			{
				printf("Checksum error. The calculated ICMP checksum does not match with the packet's checksum which is %d",checksum);
			}
			//printf("\n Hurray !! Checksum Matches for ICMP %x \n",calc_icmp_cs);
			ih->type = ICMP_ECHO_RESPONSE;
			memcpy(icmp_buf,ih,sizeof(struct sr_icmphdr));
			ih->checksum = htons(ip_sum_calc(icmp_buf_len,(uint8_t*)icmp_buf)); 
			//printf("The checksum of the ICMP Packet after modifications is %x \n",ih->checksum);
			memcpy(icmp_buf,ih,sizeof(struct sr_icmphdr));
			//Restructuring the packet.copying the icmp_buf, ethernet header and ip header back to the packet
			memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip),icmp_buf,icmp_buf_len);
			//for(int i=0;i<len;i++) printf("\nByte %d = %x",i,*(packet+i));
			//free(icmp_buf);
			sr_send_packet(sr,packet,len,interface);//send the packet
}

void PortUnreachable(struct sr_instance* sr,struct sr_ethernet_hdr* eh,
					struct ip* ipp,uint8_t* packet1,unsigned int len,char* interface,int type,int code)
{
			printf("Reached Port Unreachable");
			int len1 = 2*(sizeof(struct ip))+sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_icmpMessage)+8;
			//printf("The length is %d",len1);
			uint8_t* packet = (uint8_t*)malloc(len1);
			unsigned char *shost_addr;
			struct sr_icmpMessage* icmpMsg;
			struct sr_ethernet_hdr* eh_org;
			uint8_t* icmp_pkt_buf =(uint8_t*)malloc(36);
			uint32_t shost_ip;
			eh_org = (struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr));
			memcpy(eh_org,eh,sizeof(struct sr_ethernet_hdr));
			struct ip* ip_org;
			ip_org = (struct ip*)malloc(sizeof(struct ip));
			memcpy(ip_org,ipp,sizeof(struct ip));
			icmpMsg = (struct sr_icmpMessage*)malloc(sizeof(struct sr_icmpMessage));
			//if((Check_Router_Address(ip_org->ip_dst.s_addr,sr)) == 0)
  	        shost_addr = Retrieve_Interface_Address(interface,sr);
			shost_ip = Retrieve_IP_Address(interface,sr);
			// check the check sum value.
			uint16_t checksum = ntohs(ipp->ip_sum);
			//printf(" \n The checksum is %x \n ",checksum);
			ipp->ip_sum = 0;
			uint16_t calc_checksum_ip = (ip_sum_calc(sizeof(struct ip),(uint8_t*)ipp));
			//printf(" \n The calculated checksum is %x \n",calc_checksum_ip);
     		if((ip_sum_calc(sizeof(struct ip),(uint8_t*)ipp)) != checksum)
     		{
				printf("\n Checksum error. The calculated checksum does not match with the packet's checksum which is %d",checksum);
    		}
    		//printf("\n Hurray !! Checksum Matches for IP %x \n",calc_checksum_ip);
    		//copying the ethernet packet to the appropriate entry
			//eh->ether_type= htons(ETHERNET_IP);
			memcpy(eh->ether_dhost, eh->ether_shost, ETHER_ADDR_LEN);
			memcpy(eh->ether_shost, shost_addr, ETHER_ADDR_LEN);
            //placing the ethernet packet in the newly created packet
            memcpy(packet,eh,sizeof(struct sr_ethernet_hdr));//restructuring ethernet packet in main packet
            // copying the ip packet to the appropriate entry
            uint32_t t1 = ipp->ip_src.s_addr;
			ipp->ip_src.s_addr = shost_ip;	//ipp->ip_dst.s_addr;//
			//printf("The source address is %-.8X",ipp->ip_src.s_addr);
            ipp->ip_dst.s_addr = t1;
            ipp->ip_ttl = 200;
			ipp->ip_len = htons(len1-sizeof(struct sr_ethernet_hdr));
            ipp->ip_p = ETHERNET_ICMP;
            ipp->ip_sum = 0;
            ipp->ip_sum = htons(ip_sum_calc(sizeof(struct ip),(uint8_t*)ipp));
            //placing the IP packet in the newly created packet
            memcpy(packet+sizeof(struct sr_ethernet_hdr),ipp,sizeof(struct ip));
            //creating a new ICMP Msg
            icmpMsg->type = type;
            icmpMsg->code = code;
            icmpMsg->empty = 0;
            icmpMsg->nexthop = 0;
            icmpMsg->checksum = 0;
            //placing the icmpMsg packet in the newly created packet
            memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip),icmpMsg,sizeof(struct ip));
            //placing the ip packet and len 8 of the new packet in the newly created packet
            memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct sr_icmpMessage),ip_org,sizeof(struct ip));
            memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct sr_icmpMessage)+sizeof(struct ip),packet1+sizeof(struct ip)+sizeof(struct sr_ethernet_hdr),8);
            memcpy(icmp_pkt_buf,packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip),36);
            icmpMsg->checksum = 0;
            icmpMsg->checksum = htons(ip_sum_calc(36,(uint8_t*)icmp_pkt_buf));
            memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip),icmpMsg,sizeof(struct ip));
            memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct sr_icmpMessage),ip_org,sizeof(struct ip));
            memcpy(packet+sizeof(struct sr_ethernet_hdr)+sizeof(struct ip)+sizeof(struct sr_icmpMessage)+sizeof(struct ip),packet1+sizeof(struct ip)+sizeof(struct sr_ethernet_hdr),8);
            //printf("The interface is %s and %x",interface,*eh->ether_shost);
            //for(int i=0;i<len1;i++) printf("\nByte %d = %x",i,*(packet+i));
            sr_send_packet(sr,packet,len1,interface);
}					



// arp cache updation
void arpcache_update(uint32_t ipaddr,uint8_t* ha)
{
	//pthread_mutex_lock(&resloc);
	//printf("\n Hurray!! Going to enter my IP and hardware address in ARP Cache!! \n");
	struct arp_cache* ac = ac_head;
	int i = 0;
	while(ac)
	{
		if(ipaddr == ac->ip_addr) //IP Lookup
		{
			//printf("The address is already present in the arpcache");
			i = 1;
		}
		ac = ac->next;
	}
	if((ac == NULL) && (i == 0))
	{
		ac = malloc(sizeof(struct arp_cache));
		ac->ip_addr = ipaddr;
		memcpy(ac->ha,ha,ETHER_ADDR_LEN);
		gettimeofday(&ac->tv,NULL);
		ac->next = ac_head;
		ac_head = ac;
	}
	//printf("\n The added hardware address into the arpcache entry is %x %x \t",*(ac->ha),*((ac->ha)+1));
	//printf("\t The added ip address into the arpcache entry is %x \n",ac->ip_addr);
	//pthread_mutex_unlock(&resloc);
}

//arp cache deletion
void arpcache_deletion()
{
	//pthread_mutex_lock(&resloc);
	//printf("Entering the deletion function");
	struct arp_cache* ac = ac_head;
	struct arp_cache* ac_next;
	struct arp_cache* temp;
	//ac_next = ac->next;
	ac_next = ac;
	//If the node to be deleted is in the first location
	if(ac)
	{
		while(ac && ((TimeDiff(ac->tv)) == TRUE))
		{
			//printf("Going to delete The node until I reach the node in the first location that need not be deleted");
			temp = ac;
			ac = ac->next;
			free(temp);
			ac_head = ac;
		}
		if(ac_head)
		{
			ac = ac_head;
			ac_next = ac->next;
			while(ac_next)
			{
				if((TimeDiff(ac->tv)) == TRUE)
				{
				  if(ac_next->next == NULL)
					{
						//printf("The node is in the last location");
						ac->next = NULL;
						free(ac_next);
					}
					else
					{
						//printf("The node is in any other location");
						ac->next = ac_next->next;
						free(ac_next);
						ac_next = ac->next;
					}
				}
			 ac = ac_next;
			 ac_next = ac_next->next;
		} 
	}
	//pthread_mutex_unlock(&resloc);
}
}

int TimeDiff(struct timeval cachetime)
{
	struct timeval currenttime;
	int i = 0;
	if(((currenttime.tv_sec) - (cachetime.tv_sec)) > 15)
	{
		i = 1;
	 }
	 return i;
 } 

//arp cache - Hardware address retrieval
void RetrieveFromArpcache(uint32_t ipaddr,uint8_t* hw)
{
	//pthread_mutex_lock(&resloc);
	struct arp_cache* ac1 = ac_head;
	PrintEntriesInArpCache();
	while(ac1)
	{
		// printf("The retrieved hardware address is %x",*ac1->ha);
		if(ac1->ip_addr == ipaddr)
		{
			memcpy(hw,ac1->ha,ETHER_ADDR_LEN);
			//printf("The retrieved hardware address is %x",*hw);
		}
		ac1 = ac1->next;
	}
	//pthread_mutex_unlock(&resloc);
}

int ArpCacheLookup(uint32_t ipaddr)
{
	//pthread_mutex_lock(&resloc);
	//printf("The arpcache lookup for the address is %x",ipaddr);
	struct arp_cache* ac = ac_head;
	int a = 0;
	while(ac)
	{
		if(ac->ip_addr == ipaddr)
		{
			a = 1;
		}
		ac = ac->next;
	}
	//pthread_mutex_unlock(&resloc);
	return a;
	
}

void PrintEntriesInArpCache()
{
	//printf("Displaying the Arpcache");
	struct arp_cache* ac = ac_head;
	if(ac != NULL)
	{
	   while(ac)
		{
			//printf("\n The hardware address is %x %x \t",*(ac->ha),*((ac->ha)+1));
			//printf("\t The ip address is %x \n",ac->ip_addr);
			ac = ac->next;
		}
	}
	else {printf(" \n No entries present in the cache \n");}
}

void PacketBufferInsertion(uint8_t* pkt,unsigned int len,struct ip* ip1)
{
	int index = 1;
	//printf("Placing the packet in the buffer");
	struct packet_buffer* pb;
	pb = phead;
	int len1 = len+sizeof(struct ip)+2;
	//for(int j=0;j<len1;j++) printf("\nByte %d = %x",j,*(pkt+j));
	//pb->packet = NULL;
	while(pb)
	{
		index++;
		pb = pb->next;
	}
	if(pb == NULL)
	{
		pb =(struct packet_buffer*)malloc(len1);
		//pb =malloc(sizeof(struct packet_buffer));
		pb->packet = (uint8_t*)malloc(len);
		pb->index = index;
		pb->len = len;
		//printf("The packet's length is %d",len);
		//pb->ip_pkt= (struct ip*) malloc(sizeof(struct ip));
		pb->ip_pkt=ip1;
		pb->packet=pkt;
	//	memcpy(pb->packet,pkt,len);
	//	memcpy(pb->ip_pkt,ip1,sizeof(struct ip));
		//for(int i=0;i<len;i++) printf("\nByte %d = %x",i,*((pb->packet)+i));
		pb->next = phead;
		phead = pb;
	   }
    
}

void PacketProcessing(struct sr_instance* sr,struct sr_ethernet_hdr* eh_pkt,uint32_t ipaddr,char* interface)
{
	struct arp_cache *ac = ac_head;
	uint8_t* ether_HA = (uint8_t*)malloc(ETHER_ADDR_LEN);
	struct packet_buffer *pb1 = phead;
	//struct sr_ethernet_hdr* eh1 = eh_pkt;
	unsigned int len = pb1->len;
	uint8_t* packet1 = pb1->packet;
	if(ac->ip_addr == ipaddr)
	{
		ether_HA = ac->ha;
	}
	//for(int j=0;j<len;j++) printf("\nByte %d = %x",j,*((pb->packet)+j));
	if(pb1 == NULL)
	{
		printf("No entry in the buffer");
	}
	else
	{
		printf("Incoming IP address is %x \n",ipaddr);
		while(pb1)
		{
			if(ipaddr == (uint32_t)pb1->ip_pkt->ip_dst.s_addr)
			{
				printf("Entered Packet processing***********************");
				//memcpy(eh1->ether_dhost,ether_HA,ADDR_LEN);
				memcpy(packet1,ether_HA,ETHER_ADDR_LEN);
				//for(int i=0;i<len;i++) printf("\nByte %d = %x",i,*(packet1+i));
				sr_send_packet(sr,packet1,len,interface);//send the packet
				pb1->len = 0;
				//printf("The index is %d",pb1->index);
				//PacketBufferDeletion(pb->index);
			}
			pb1 = pb1->next;
		}
	}
}


void PacketBufferDeletion(int i)
{
		//printf("Entering the deletion function");
		struct packet_buffer* pb = phead;
		struct packet_buffer* temp;
		struct packet_buffer* pb_prev;
		pb_prev = pb;
		if(pb == NULL)
		{
			return;
		}
		//If the node to be deleted is in the first location
		if(pb->index == i)
		{
			printf("The node is in the first location");
			temp = pb;
			if(pb->next != NULL)
			{
				
				pb = pb->next;
				printf("The current index is %x",pb->index);
			}
			else
			{
				pb = 0;
			}
			free(temp);
			return;
		}
		//If it is elseewhere
		while(pb->next)
		{
			pb_prev = pb;
			pb = pb->next;
			if(pb->index == i)
			{
				//If it is in the last node
				temp = pb;
				if(pb->next == NULL)
				{
					printf("The node is in the last location %d",pb->index);
					pb_prev->next = NULL;
				}
				else
				{
					printf("Going to delete %d",pb->index);
					pb_prev->next = pb->next;
				}
				free(temp);
				return;
			}
	}
}

	
	
/* FUNCTION TO CALCULATE CHECKSUM IS TAKEN FROM THE 
 * INTERNET http://www.netfor2.com/ipsum.htm. Both of the authors do not 
 * claim ownership of the below
**************************************************************************
Function: ip_sum_calc
Description: Calculate the 16 bit IP sum.
***************************************************************************
*/

uint16_t ip_sum_calc(uint16_t len_ip_header, uint8_t buff[])
{
uint16_t word16;
uint32_t sum=0;
uint16_t i;
    
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for (i=0;i<len_ip_header;i=i+2){
		word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		sum = sum + (uint32_t) word16;	
	}
	
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum>>16)
	  sum = (sum & 0xFFFF)+(sum >> 16);

	// one's complement the result
	sum = ~sum;
	
return ((uint16_t) sum);
}	




	
	
