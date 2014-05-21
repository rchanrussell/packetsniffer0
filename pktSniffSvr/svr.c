/*
 * svr.c - simple server for receiving packets and saving to file
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <pcap.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <netinet/if_ether.h>

#include <sys/types.h>
#include <sys/time.h>
/*
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
*/

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

/*
 * handle zombie processes after forked processes are complete
 */
void sigchld_handler(int s)
{
  while(waitpid(-1, NULL, WNOHANG) > 0);
}

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr,
                           const u_char* packet) {
  struct ether_header *eptr;
  /* ethernet header */
  eptr = (struct ether_header *) packet;
  fprintf(stdout,"ETH: %s",
          ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
  fprintf(stdout," %s ",
          ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

  /* check if IP packet */
  if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
    fprintf(stdout, "(IP)");
  } else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
    fprintf(stdout,"(ARP)");
  } else if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP) {
    fprintf(stdout,"(RARP)");
  } else {
    fprintf(stdout, "(?)");
    exit(1);
  }
  
  fprintf(stdout,"\n");

  return (ntohs (eptr->ether_type));
}

/* tcp */
u_char* handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  fprintf(stdout,"\n...processing TCP packet\n");
  return NULL;
}

/* udp */
u_char* handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  fprintf(stdout,"\n...processing UDP packet\n");
  return NULL;
}

/* icmp */
u_char* handle_ICMP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  fprintf(stdout,"\n...processing ICMP packet\n");
  return NULL;
}

/* igmp */
u_char* handle_IGMP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  fprintf(stdout,"\n...processing IGMP packet\n");
  return NULL;
}

/* determine which protocol to process */
u_char* getProtocol (u_int8_t protocol, u_char *args, const struct pcap_pkthdr* pkthdr,
                     const u_char* packet) {
  switch(protocol) {
    case 1:
      fprintf(stdout,"(ICMP)");
      handle_ICMP(args,pkthdr,packet);
      break;
    case 2:
      fprintf(stdout,"(IGMP)");
      handle_IGMP(args,pkthdr,packet);
      break;
    case 3:
      fprintf(stdout,"(GGP)");
      break;
    case 4:
      fprintf(stdout,"(IPv4enc)");
      break;
    case 5:
      fprintf(stdout,"(ST)");
      break;
    case 6:
      fprintf(stdout,"(TCP)");
      handle_TCP(args,pkthdr,packet);
      break;
    case 17:
      fprintf(stdout,"(UDP)");
      handle_UDP(args,pkthdr,packet);
      break;
    case 41:
      fprintf(stdout,"(IPv6enc)");
      break;
    case 58:
      fprintf(stdout,"(IPv6-ICMP)");
    default:
      fprintf(stdout,"(protocol %d)\n", protocol);
  }
  fprintf(stdout,"\n");
  return NULL;
}

u_char* handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  const struct my_ip* ip;
  u_int length = pkthdr->len;
  u_int hlen, off, version;
  int i;
  int len;

  /* skip past ethernet header */
  ip = (struct my_ip*)(packet + sizeof(struct ether_header));
  length -= sizeof(struct ether_header);

  /* check if packet is of valid length */
  if (length < sizeof(struct my_ip)) {
    printf("tuncated IP %d", length);
    return NULL;
  }

  len = ntohs(ip->ip_len);
  hlen = IP_HL(ip);
  version = IP_V(ip);

  /* check version */
  if (version != 4) {
    fprintf(stdout, "Unknown version %d\n", version);
    return NULL;
  }

  /* check header length */
  if (hlen < 5) {
    fprintf(stdout, "bad-hlen %d\n", hlen);
  }

  /* see if any bytes missing from packet */
  if (length < len) {
    fprintf(stdout,"\n truncated IP - %d bytes missing!\n", len - length);
  }

  /* check if have first fragment */
  off = ntohs (ip->ip_off);
  if ((off & 0x1fff) == 0) /* no 1's in first 13 bites */
  {
    /* print SOURCE DESTINATION hlen version len offset */
    fprintf(stdout, "IP: ");
    fprintf(stdout, "%s ", inet_ntoa(ip->ip_src));
    fprintf(stdout, "%s %d %d %d %d ",
            inet_ntoa(ip->ip_dst),
            hlen, version, len, off);
    getProtocol(ip->ip_p,args,pkthdr,packet);
  }

  return NULL;
}



void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  u_int16_t type = handle_ethernet(args,pkthdr,packet);
  if (type == ETHERTYPE_IP) {
    /* IP packet */
    handle_IP(args, pkthdr, packet);
  } else if (type == ETHERTYPE_ARP) {
    /* ARP packet */
  
  } else if (type == ETHERTYPE_REVARP) {
    /* reverse ARP packet */  
  }
  fflush(stdout);
}

int main(int argc, char **argv)
{
  int i;
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
  const u_char *packet;
  struct pcap_pkthdr hdr; /* pcap.h */
  struct ether_header *eptr; /* net/ethernet.h */
  struct bpf_program fp; /* hold compiled program */
  bpf_u_int32 maskp; /* subnet mask */
  bpf_u_int32 netp; /* ip */

  if(argc != 4) {
    fprintf(stdout, "Usage: %s numpackets device \"filter program\"\n", argv[0]);
    fprintf(stdout, "agrc %d\n", argc);
    return 0;
  }

  u_char *ptr; /* print hardware header info */

  /* grab device to peak into */
  dev = pcap_lookupdev(errbuf);

  if (dev == NULL)
  {
    printf("%s\n", errbuf);
    exit(1);
  }

  printf("Changing dev...\n");
  dev = argv[2];
  printf("DEV: %s\n", dev);

  /* ask pcap for network addr and mask fo device */
  pcap_lookupnet(dev,&netp,&maskp,errbuf);

  /* open device for sniffing */
  /*
   * pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
   *    char *ebuf)
   *
   *    snaplen - maximum size of packets to capture in bytes
   *    promisc - set card in promiscuous mode?
   *    to_ms   - time to wait for packets in miliseconds before read
   *    times out
   *    errbuf  - if something happens, place error string here
   *
   *    Note if you change "prmisc" param to anything other than zero, you will
   *    get all packets your device sees, whether they are intendeed for you or
   *    not!! Be sure you know the rules of the network you are running on
   *    before you set your card in promiscuous mode!!    
   */
  /* set to permiscuous 1 if monitoring traffic to other machines, 0 for this machine */
  descr = pcap_open_live(dev,BUFSIZ,1,5000,errbuf);

  if(descr == NULL)
  {
    printf("pcap_open_live(): %s\n", errbuf);
    exit(1);
  }

  /* compile program, passed param, like host www.google.ca */
  if (pcap_compile(descr,&fp,argv[3],0,netp) == -1) {
    fprintf(stderr, "Error calling pcap_compile\n");
    perror("pcap_compile");
    exit(1);
  }

  /* set compiled program as filter */
  if (pcap_setfilter(descr,&fp) == -1) {
    fprintf(stderr, "Error setting filter\n");
    perror("pcap_setfilter");
    exit(1);
  }

  /* call pcap_loop() and pass callback function
   * int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
   */
  pcap_loop(descr, atoi(argv[1]), my_callback, NULL);

  fprintf(stdout, "\nDone processing packets\n");

  return 0;

}

