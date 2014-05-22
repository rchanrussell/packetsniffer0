/*
 * svr.c - simple server for receiving packets and saving to file
 */

#include "svr.h"

int main(int argc, char **argv)
{
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
  struct bpf_program fp; /* hold compiled program */
  bpf_u_int32 maskp; /* subnet mask */
  bpf_u_int32 netp; /* ip */

  if(argc != 4) {
    fprintf(stdout, "Usage: %s numpackets device \"filter program\"\n", argv[0]);
    fprintf(stdout, "32pkts on Ethernet for port 80 - Ex: %s 32 eth0 \"port 80\"\n",argv[0]);
    fprintf(stdout, "2pkts on second port from machine ip - Ex: %s 2 en1 \"src 192.168.1.1\"\n",argv[0]);
    fprintf(stdout, "64pkts on eth0 any port, in or out - Ex: %s 64 eth0 \"ip\"\n",argv[0]);
    return 0;
  }


  /* grab device to peak into */
  dev = pcap_lookupdev(errbuf); /* always grabs inactive ones,but code exits without */

  if (dev == NULL)
  {
    printf("%s\n", errbuf);
    exit(1);
  }

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
  descr = pcap_open_live(dev,BUFSIZ,1,100,errbuf);

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

  pcap_close(descr);
  return 0;
}

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr,
                           const u_char* packet) {
  struct my_ether_header *eptr;
  /* ethernet header */
  eptr = (struct my_ether_header *) packet;
  fprintf(stdout,"ETH: %s",
          my_ether_ntoa((const struct my_ether_addr *)&eptr->ether_shost));
  fprintf(stdout," %s ",
          my_ether_ntoa((const struct my_ether_addr *)&eptr->ether_dhost));

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
  const struct my_tcphdr* tcp;
  u_int length = pkthdr->len;
  u_short srcPort;
  u_short dstPort;
  u_int32_t seq;
  u_int32_t ack;
  u_char flags;
  u_char hlen;

  /* move past ethernet and IP packet headers */
  tcp = (struct my_tcphdr*)(packet + sizeof(struct my_ether_header) + sizeof(struct my_ip));
  length -= sizeof(struct my_ether_header) + sizeof(struct my_ip);

  /* ensure tcp is valid length */
  if (length < sizeof(struct my_tcphdr)) {
    fprintf(stdout,"handle_TCP: truncated TCP packet %d\n", length);
    return NULL;
  }

  hlen = tcp->th_off;

  /* check header length */
  if(hlen < 5) {
    fprintf(stdout, "handle_TCP: bad-hlen %d\n",hlen);
  }

  /* process packet */
  srcPort = ntohs(tcp->th_sport);
  dstPort = ntohs(tcp->th_dport);
  seq = ntohl(tcp->th_seq);
  ack = ntohl(tcp->th_ack);
  flags = tcp->th_flags;

  fprintf(stdout,"\nTCP: ");
  fprintf(stdout,"%d %d %x %x %x\n",srcPort,dstPort,
                 seq,ack,flags);

  return NULL;
}

/* udp */
u_char* handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  const struct my_udphdr* udp;
  u_int length = pkthdr->len;
  u_short srcPort;
  u_short dstPort;
  u_short pktLen;

  /* move past ethernet and IP packet headers */
  udp = (struct my_udphdr*)(packet + sizeof(struct my_ether_header) + sizeof(struct my_ip));
  length -= sizeof(struct my_ether_header) + sizeof(struct my_ip);
  pktLen = udp->uh_ulen;

  /* ensure udp is valid length */
  if (length < sizeof(struct my_udphdr)) {
    fprintf(stdout,"handle_UDP: truncated UDP packet %d\n", length);
    return NULL;
  }

  /* check header length */
  if(pktLen < sizeof(struct my_udphdr)) {
    fprintf(stdout, "handle_UDP: bad-packetlen %d\n",pktLen);
  }

  /* process packet */
  srcPort = ntohs(udp->uh_sport);
  dstPort = ntohs(udp->uh_dport);

  fprintf(stdout,"\nUDP: ");
  fprintf(stdout,"%d %d %d\n",srcPort,dstPort,pktLen);

  return NULL;

}

/* icmp */
u_char* handle_ICMP (u_char *args, const struct pcap_pkthdr* pkthdr,
                   const u_char* packet) {
  const struct my_icmphdr* icmp;
  u_int length = pkthdr->len;
  u_char type;
  u_char code;

  /* move past ethernet and IP packet headers */
  icmp = (struct my_icmphdr*)(packet + sizeof(struct my_ether_header) + sizeof(struct my_ip));
  length -= sizeof(struct my_ether_header) + sizeof(struct my_ip);

  /* ensure udp is valid length */
  if (length < sizeof(struct my_icmphdr)) {
    fprintf(stdout,"handle_ICMP: truncated ICMP packet %d\n", length);
    return NULL;
  }

  /* process packet */
  type = icmp->icmp_type;
  code = icmp->icmp_code;

  fprintf(stdout,"\nICMP: ");
  fprintf(stdout,"%d %d\n",type,code);

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
      fprintf(stdout,"(IGMP)\n");
      break;
    case 3:
      fprintf(stdout,"(GGP)\n");
      break;
    case 4:
      fprintf(stdout,"(IPv4enc)\n");
      break;
    case 5:
      fprintf(stdout,"(ST)\n");
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
      fprintf(stdout,"(IPv6enc)\n");
      break;
    case 58:
      fprintf(stdout,"(IPv6-ICMP)\n");
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
  int len;

  /* skip past ethernet header */
  ip = (struct my_ip*)(packet + sizeof(struct my_ether_header));
  length -= sizeof(struct my_ether_header);

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

char * my_ether_ntoa_r(const struct my_ether_addr *n, char *a) {
  int i;
  i = sprintf(a, "%02x:%02x:%02x:%02x:%02x:%02x", n->octet[0],
        n->octet[1], n->octet[2], n->octet[3], n->octet[4], n->octet[5]);
  if (i < 17) {
    return (NULL);
  }
  return (a);
}

char * my_ether_ntoa(const struct my_ether_addr *n) {
  static char a[18];
  return (my_ether_ntoa_r(n,a));
}


