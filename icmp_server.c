#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "key_gen.h"
#include "rc4.h"
#include "icmp_test.h"

pthread_t thread_eth_reader;
int recv_len_min;

unsigned short cal_chksum(unsigned short *addr,int len)
{
  int nleft=len;
  int sum=0;
  unsigned short *w=addr;
  unsigned short answer=0;
  while(nleft>1)
  {
    sum+=*w++;
    nleft-=2;
  }
  if( nleft==1)
  {
    *(unsigned char *)(&answer)=*(unsigned char *)w;
    sum+=answer;
  }
  sum=(sum>>16)+(sum&0xffff);
  sum+=(sum>>16);
  answer=~sum;
  return answer;
}

int main(int argc, char**argv)
{
  int sockfd,n;
  struct sockaddr_in servaddr;
  int addr_len = sizeof(servaddr);
  uint8_t recvline[1000];
  char *key = "a icmp test ^&-";
  recv_len_min = IP_HEAD_LEN + sizeof(icmp_packet_t) + 2;

  srand((int)time(0)); 
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  //sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  while(1)
  {
    memset(recvline,0,1000);
    n = recvfrom(sockfd,recvline,1000,0,(struct sockaddr *)&servaddr,(socklen_t *)&addr_len);
    if(n <= recv_len_min) continue;
    int pkt_len = n - IP_HEAD_LEN;
    int msg_len = pkt_len - sizeof(icmp_packet_t);
    icmp_packet_t *pkt = (icmp_packet_t *)(recvline + IP_HEAD_LEN);

    unsigned short seq = ntohs(pkt->seq);
    if(seq < MIN_SEQ) continue;
    unsigned char key_new[16];
    key_gen(key, key_new, seq);

    struct rc4_state S_box;
    rc4_init(&S_box,key_new,16);
    rc4_crypt(S_box,pkt->data,pkt->data,msg_len);

    if(pkt->data[0] != 0x08 || pkt->data[1] != 0x09)
    {
      continue;
    }
    pkt->data[msg_len] = 0;
    fprintf(stderr,"MSG RECIVED -------------------\n%s\n",pkt->data+2);
    pkt->data[1] = 0x0a;
    pkt->type = 0;
    pkt->checksum = 0;

    rc4_crypt(S_box,pkt->data,pkt->data,msg_len);
    pkt->checksum = cal_chksum((uint16_t*)pkt, pkt_len);
    sendto(sockfd,(char *)pkt,pkt_len,0,
      (struct sockaddr *)&servaddr,sizeof(servaddr));
  }
  return 0;
}


