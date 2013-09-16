#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h> 

#include "key_gen.h"
#include "rc4.h"
#include "timer.h"
#include "icmp_test.h"

pthread_t thread_eth_reader;
int recv_len_min;
struct sockaddr_in servaddr;
static pthread_mutex_t info_mutex;

icmp_info_t *info_list;
icmp_info_t *info_head = NULL;
int info_num = 0;

void destroy_info()
{
  icmp_info_t *tmp = NULL;
  icmp_info_t *p = info_head;
  pthread_mutex_lock(&info_mutex);
  while(p)
  {
    tmp = p;
    p = p->next;
    free(tmp);
  }
  info_head = NULL;
  info_num = 0;
  pthread_mutex_unlock(&info_mutex);
}

icmp_info_t *push_info(unsigned short seq, struct rc4_state S_box)
{
  if(info_num >= MAX_INFO_NUM)
    destroy_info();

  pthread_mutex_lock(&info_mutex);
  icmp_info_t *tmp = NULL;
  icmp_info_t *p = info_head;
  while(p)
  {
    if(p->seq == seq)
      return NULL;
    tmp = p;
    p = p->next;
  }
  p = (icmp_info_t *)malloc(sizeof(icmp_info_t));
  p->next = NULL;
  p->seq = seq;
  p->S_box = S_box;
  p->time = curr_time;
  if(tmp != NULL)
    tmp->next = p;
  else info_head = p;
  info_num++;
  pthread_mutex_unlock(&info_mutex);
  return p;
}

icmp_info_t *get_info(unsigned short seq)
{
  pthread_mutex_lock(&info_mutex);
  icmp_info_t *tmp = NULL;
  icmp_info_t *p = info_head;
  while(p)
  {
    if((curr_time - p->time) >= 10)
    {
      //fprintf(stderr,"time out \n");
      if(tmp != NULL)tmp->next = p->next;
      else info_head = p->next;
      free(p);
      info_num--;
      if(tmp != NULL)p = tmp->next;
      else if(info_head != NULL)p = info_head->next;
      else return NULL;
      continue;
    }
    if(p->seq == seq)
    {
      pthread_mutex_unlock(&info_mutex);
      return p;
    }
    tmp = p;
    p = p->next;
  }
  pthread_mutex_unlock(&info_mutex);
  return NULL;
}

void del_info(unsigned short seq)
{
  pthread_mutex_lock(&info_mutex);
  icmp_info_t *tmp = NULL;
  icmp_info_t *p = info_head;
  while(p)
  {
    if(p->seq == seq)
    {
      if(tmp != NULL)tmp->next = p->next;
      else info_head = p->next;
      free(p);
      p = NULL;
      info_num--;
      pthread_mutex_unlock(&info_mutex);
      return;
    }
    tmp = p;
    p = p->next;
  }
  pthread_mutex_unlock(&info_mutex);
  return;
}

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

void* eth_reader(void *arg)
{
  int n;
  uint8_t recvline[1000];
  if(arg == NULL)return NULL;
  int sockfd = *(int *)arg;
  fd_set rfds;

  while(1)
  {
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    select(sockfd + 1, &rfds, NULL, NULL, NULL);
    struct sockaddr_in recvaddr;
    socklen_t addr_len = sizeof(recvaddr);
    n = recvfrom(sockfd,recvline,1000,0,(struct sockaddr *)&recvaddr,&addr_len);
    if(n <= recv_len_min) continue;
    if(servaddr.sin_addr.s_addr != recvaddr.sin_addr.s_addr) continue;

    int msg_len = n - IP_HEAD_LEN - sizeof(icmp_packet_t);
    icmp_packet_t *pkt = (icmp_packet_t *)(recvline+IP_HEAD_LEN);
    unsigned short seq = ntohs(pkt->seq);

    icmp_info_t *info;
    info = get_info(seq);
    if(info == NULL)
      continue;
    if(seq != info->seq || seq < MIN_SEQ)
      continue;

    rc4_crypt(info->S_box, pkt->data, pkt->data, msg_len);
    if(pkt->data[0] != 0x08 || pkt->data[1] != 0x0a)
    {
      continue;
    }

    del_info(seq);
    pkt->data[msg_len] = 0;
    fprintf(stderr,"MSG RECIVED -------------------\n%s\n",pkt->data+2);
  }
}


int main(int argc, char**argv)
{
  int sockfd;
  char *key = "a icmp test ^&-";

  uint8_t sendline[1000];
  if (argc < 2)
  {
     printf("client usage:  client <IP address>\n");
     return -1;
  }
  srand((int)time(0)); 
  start_timer();
  pthread_mutex_init(&info_mutex, NULL);

  recv_len_min = IP_HEAD_LEN + sizeof(icmp_packet_t) + 2;

  //sockfd = socket( AF_INET, SOCK_DGRAM, IPPROTO_ICMP );
  sockfd = socket( AF_INET, SOCK_RAW, IPPROTO_ICMP );
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr=inet_addr(argv[1]);
  pthread_create(&thread_eth_reader, NULL, &eth_reader, (void *)&sockfd);

  while (fgets((char*)sendline, 1000,stdin) != NULL)
  {
    int count = 0;

    uint16_t identifier = rand();
    uint16_t seq = (rand()%(INT16_MAX-MIN_SEQ)) + MIN_SEQ;
    while(get_info(seq) != NULL)
    {
      if(count >=3)return -1;
      count++;
      seq = (rand()%(INT16_MAX-MIN_SEQ)) + MIN_SEQ;
    }

    uint16_t msg_id = htons(MSG_HEAD_CLIENT);
    unsigned char key_new[16];
    int msg_len = strlen((char *)sendline);
    key_gen(key, key_new, seq);
    int pkt_len = sizeof(icmp_packet_t) + msg_len + 2;
    icmp_packet_t* pkt = malloc(pkt_len + 1);
    pkt->type = 8;
    pkt->code = 0;
    pkt->checksum = 0;
    pkt->identifier = htons(identifier);
    pkt->seq = htons(seq);
    memcpy(pkt->data, (char *)&msg_id, 2);
    memcpy(pkt->data+2, sendline, msg_len);

    struct rc4_state S_box;
    rc4_init(&S_box,key_new,16);
    rc4_crypt(S_box,pkt->data,pkt->data,msg_len+2);
    push_info(seq, S_box);

    pkt->checksum = cal_chksum((uint16_t*)pkt, pkt_len);
    sendto(sockfd, pkt, pkt_len, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    free(pkt);
  }
  return 0;
}
