#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "version.h"

int key_gen(char *key,unsigned char out[16],unsigned short salt)
{
  MD5_CTX ctx;
  MD5_Init(&ctx);
  //int len = strlen(key);
  //char data[len+40];
  char *data = (char *)malloc(strlen(key)+40);
  sprintf(data,"%u14%saI%s",salt,_VERSION_H,key);
  MD5_Update(&ctx, (void *)data, strlen(data));
  free(data);
  MD5_Final(out,&ctx);
  
  return 0;
}
