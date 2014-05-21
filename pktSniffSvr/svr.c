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

/*
 * handle zombie processes after forked processes are complete
 */
void sigchld_handler(int s)
{
  while(waitpid(-1, NULL, WNOHANG) > 0);
}

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  //struct pcap_pkthdr hdr; /* pcap.h */
  struct ether_header *eptr; /* net/ethernet.h */
  u_char *ptr; /* print hardware header info */
  int i;
  static int count = 1;
  fprintf(stdout, "PktCount: %d \n", count);

  if (packet == NULL)
  {
    printf("Didn't grab packet\n");
    exit(1);
  }

  /*
   * struct pcap_pkthdr {
   *   struct timeval ts;   time stamp
   *   bpf_u_int32 caplen;  length of portion present
   *   bpf_u_int32;         length of packet off wire
   */

  printf("Grabbed packet of length %d\n",pkthdr->len);
  printf("Received at .... %s\n",ctime((const time_t*)&pkthdr->ts.tv_sec));
  printf("Ethernet address length is %d\n", ETHER_HDR_LEN);

  /*
   * ether header
   */
  eptr = (struct ether_header *) packet;

  /* check type of packet */
  if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
  {
    printf("Ethernet type hex:%x dec:%d is an IP packet\n",
            ntohs(eptr->ether_type),
            ntohs(eptr->ether_type));
  } else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
  {
    printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
            ntohs(eptr->ether_type),
            ntohs(eptr->ether_type));
  } else {
    printf("Ethernet type %x not IP\n", ntohs(eptr->ether_type));
    exit(1);
  }
  
  ptr = eptr->ether_dhost;
  i = ETHER_ADDR_LEN;
  printf(" Destination Address:  ");
  do {
    printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
  }while(--i>0);
  printf("\n");

  ptr = eptr->ether_shost;
  i = ETHER_ADDR_LEN;
  printf(" Source Address:  ");
  do {
    printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
  } while(--i>0);
  printf("\n");

  fflush(stdout);
  count++;
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

