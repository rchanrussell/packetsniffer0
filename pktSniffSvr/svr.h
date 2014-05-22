/*
 * svr.h - simple server header file for receiving packets and saving to file
 */
#ifndef _PKTSNIFFSVR_H_
#define _PKTSNIFFSVR_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#ifdef _LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#else
#include <netinet/if_ether.h>
#endif

#define MY_ETHER_ADDR_LEN 6

/*
 * Structures
 * write own to improve portability
 * mostly are direct copies of BSD
 */
struct my_ether_header {
  u_char ether_dhost[MY_ETHER_ADDR_LEN];
  u_char ether_shost[MY_ETHER_ADDR_LEN];
  u_short ether_type;
};
struct my_ether_addr {
  u_char octet[MY_ETHER_ADDR_LEN];
};

struct my_ip {
  u_int8_t  ip_vhl; /* header lenght, version */
#define IP_V(ip)  (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
  u_int8_t  ip_tos; /* type of service */
  u_int16_t ip_len; /* total length */
  u_int16_t ip_id;  /* identification */
  u_int16_t ip_off; /* fragment offset field */
#define IP_DF 0x4000  /* don't fragment flag */
#define IP_MF 0x2000  /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
  u_int8_t  ip_ttl; /* time to live */
  u_int8_t  ip_p;   /* protocol */
  u_int16_t ip_sum; /* checksum */
  struct in_addr ip_src,ip_dst; /* source and destination addresses */
};

struct my_icmphdr { /* because netinet/ip_icmp.h has type issues */
  u_char icmp_type;
  u_char icmp_code;
  u_short icmp_cksum;
};

struct my_tcphdr { /* try to improve portability since this won't work on Linux */
  u_short th_sport;
  u_short th_dport;
  u_int32_t th_seq;
  u_int32_t th_ack;
#if BYTE_ORDER == LITTLE_ENDIAN
  u_char th_x2:4,
         th_off:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
  u_char th_off:4,
         th_x2:4;
#endif
  u_char th_flags;
  u_short th_win;
  u_short th_sum;
  u_short th_urp;
};

struct my_udphdr {
  u_short uh_sport;
  u_short uh_dport;
  u_short uh_ulen;
  u_short uh_sum;
};

/*
 * Function Prototypes 
 */

/*
 * ether to address
 */
char *my_ether_ntoa(const struct my_ether_addr *);
char *my_ether_ntoa_r(const struct my_ether_addr *n, char *a);

/*
 * Ethernet packet
 */
u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr,
                           const u_char* packet); 
  
/* 
 * TCP packet
 */
u_char* handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet);

/*
 * UDP packet
 */
u_char* handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet);

/*
 * ICMP packet
 */
u_char* handle_ICMP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet);

/*
 * IP packet
 */
u_char* handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet);

/*
 * Process Protocl Selector
 */
u_char* getProtocol (u_int8_t protocol, u_char *args, const struct pcap_pkthdr* pkthdr,
                     const u_char* packet);

/*
 * Callback used by pcap_loop
 */
void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif
