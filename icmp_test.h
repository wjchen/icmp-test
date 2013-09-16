#ifndef _ICMP_TEST_h
#define _ICMP_TEST_h

#define MSG_HEAD_CLIENT 0x0809
#define MSG_HEAD_SERVER 0x080a
#define IP_HEAD_LEN 20
#define MAX_INFO_NUM 1024
#define MIN_SEQ 1024


typedef struct icmp_packet_s{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t seq;
  unsigned char data[0];
} icmp_packet_t;

typedef struct icmp_info_s {
  uint16_t seq;
  struct rc4_state S_box;
  int time;
  struct icmp_info_s* next;
} icmp_info_t;


#endif