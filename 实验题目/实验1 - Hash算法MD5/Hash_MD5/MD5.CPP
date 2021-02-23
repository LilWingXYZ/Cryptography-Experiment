#include <string.h>
#include <iostream>
#include <stdlib.h>
#include "MD5C.C"

void main(int argc, char* argv[])
{

  FILE *fp;
  unsigned char line[1000];
  unsigned char digest[16]; //用于保存最终的散列值
  if(NULL ==(fp= fopen("filename.txt", "r" )))
  { 
     printf("open file error");
     exit(0);
  }
  MD5_CTX context;  //上下文变量 
  //unsigned char s_input[] = "hello,world"; //要处理的串
  
     
  //利用三个函数产生散列值
   
   MD5Init (&context);
   while(fgets((char *)line, 1000, fp))
  {
     //对line进行处理;
	MD5Update (&context, line, strlen((char *)line));
  }
     
   MD5Final (digest, &context);
    
  //以十六进制字符串形式输出128位散列值
    for (int i=0; i<16; i++)
	printf("%x", digest[i]);
    printf("\n");

    fclose( fp ); 
}
