//#include "stdafx.h"
#include <string.h>
#include <stdlib.h>
#include "R_STDLIB.C"
#include "MD5C.C"
#include "DESC.C"
#include "R_RANDOM.C"
#include <stdio.h>

//以十六进制形式显示output中的内容
void shows (char * msg, unsigned char *output, int len)
{  
   printf("%s: ", msg);
   for (int i=0; i<len; i++)
	   printf("%x", output[i]);
   printf("\n");
}

//填充随机数结构体
void seed_randomStruct (unsigned char *seed, R_RANDOM_STRUCT *randomStruct)
{
    unsigned int bytesNeeded = 256;  //结构体所需种子长度

    R_RandomInit (randomStruct);	
    while (bytesNeeded > 0)
    { 
       R_RandomUpdate (randomStruct, seed, 
                                       strlen((char *)seed));
	   R_GetRandomBytesNeeded (&bytesNeeded, 
                                                        randomStruct);
	}
}

//将input和mac中的内容复制到plaintext中
void combines (unsigned char *plaintext, unsigned char *input, unsigned char mac[8], int inputlen)
{   
	for (int i=0; i< inputlen; i++)
       plaintext[i] = input[i];

	for (int j=0; j<8; j++)
	   plaintext[inputlen+j] = mac[j];
}

//将恢复后明文中的内容拆分到output和mac
void decombines (unsigned char *plaintext, unsigned char *output, unsigned char mac[8], int outputlen)
{   
	for (int i=0; i< outputlen; i++)
       output[i] = plaintext[i];
	output[outputlen] = '\0';

	for (int j = 0; j < 8; j++)
	   mac [j] = plaintext[outputlen+j];
}

//产生MAC
void create_MAC(unsigned char mac_output[8], unsigned char *input, 
		                int len, unsigned char key[8], unsigned char iv[8])
{
   unsigned char *output;
   DES_CBC_CTX  context;

   output = new unsigned char[len];

   DES_CBCInit(&context, key, iv, 1);
   DES_CBCUpdate(&context, output, input, len);

   for (int i=0; i<8;i++)
	   mac_output[i] = output[len-8+i];

   delete []output;
}

//比较收到的MAC和对收到消息产生的MAC
int compares(unsigned char received_mac[8], 
                      unsigned char new_mac[8])
{
	for(int i=0; i<8; i++)
	{
		if (received_mac[i] != new_mac[i])
		     return 0;
	}
	return 1;
}

#define TEXT_LEN  16  // 消息长度
#define PLAINTEXT_LEN   TEXT_LEN + 8 // 明密文长度(不包括字符串末尾的'\0')
int main(int argc, char* argv[])
{  
unsigned char seed[] = "12312ae12qweqweqweqe";
unsigned char key1[8], key2[8], iv1[8]={0}, iv2[8];
unsigned char input[TEXT_LEN+1] = "12345678abcdefgh"; // 保存发送的消息
unsigned char mac[8];                                    // 保存对发送消息产生的MAC
unsigned char plaintext[PLAINTEXT_LEN];   // 保存明文
unsigned char ciphertext[PLAINTEXT_LEN]; // 保存密文
unsigned char plaintext2[PLAINTEXT_LEN]; // 保存恢复的明文
unsigned char output[TEXT_LEN+1]; // 保存恢复后的消息
unsigned char received_mac[8];        // 保存恢复后的MAC
unsigned char new_mac [8];              // 保存对接收到的消息产生的MAC

R_RANDOM_STRUCT randomStruct;
DES_CBC_CTX  context;

seed_randomStruct (seed, &randomStruct);
//产生密钥和IV, 分别用于产生MAC和加解密
R_GenerateBytes (key1, 8, &randomStruct);
R_GenerateBytes (key2, 8, &randomStruct);
R_GenerateBytes (iv2, 8, &randomStruct);
// 显示发送消息
printf ("sent message: %s\n", input);

//对发送的消息产生MAC
create_MAC(mac, input, TEXT_LEN, key1, iv1);

// 显示MAC
shows("sent MAC", mac, 8);

//组合消息和MAC为明文
combines (plaintext, input, mac, TEXT_LEN);

//加密
DES_CBCInit(&context, key2, iv2, 1);
DES_CBCUpdate(&context, ciphertext, plaintext,   
                               PLAINTEXT_LEN);

// 显示密文
shows("ciphertext", ciphertext, PLAINTEXT_LEN);

//ciphertext[10] = ciphertext[10] + 1; //改变密文的一个字节

//解密
DES_CBCInit(&context, key2, iv2, 0);
DES_CBCUpdate(&context, plaintext2, ciphertext, 
                              PLAINTEXT_LEN);

//将密文中的内容拆分到output和received_mac
decombines (plaintext2, output, received_mac, TEXT_LEN);

//显示解密后的消息和MAC
printf("reveived message: %s\n", output);
shows("received MAC", received_mac, 8);

//对收到的消息产生MAC, 并显示
create_MAC(new_mac, output, TEXT_LEN, key1, iv1);
shows("MAC for received message", new_mac, 8);

//校验MAC
if (compares(received_mac, new_mac))
  printf ("received message OK!\n");
else
  printf ("received message ERROR!\n");

R_RandomFinal (&randomStruct);

return 0; 
}





 