//#include "stdafx.h"
#include <string.h>
#include "R_STDLIB.C"
#include "R_RANDOM.C"
#include "MD5C.C"
#include "DESC.C"
#include <stdio.h>

//以十六进制形式显示output中的内容
void shows (unsigned char *output, int len)
{  printf ("ciphertext: ");
   for (int i=0; i<len; i++)
	   printf("%x", output[i]);
   printf("\n");
}

//将output中的内容复制到input中
void copys (unsigned char *output, unsigned char *input, int len)
{   for (int i=0; i< len; i++)
         input[i] = output[i];
}

//产生salt
void create_salt (unsigned char *salt, int saltlen, unsigned char *seed)
{
	R_RANDOM_STRUCT randomStruct;  //随机数结构体
    unsigned int bytesNeeded = 256;          //结构体所需种子长度

    R_RandomInit (&randomStruct);	
    while (bytesNeeded > 0)
    {   
       R_GetRandomBytesNeeded (&bytesNeeded, &randomStruct);
       R_RandomUpdate (&randomStruct, seed, strlen((char *)seed));
	}
    R_GenerateBytes (salt, saltlen, &randomStruct);
    R_RandomFinal (&randomStruct);
}
//用MD5混合口令和salt
void MixPwdSalt (unsigned char *password, 
                            unsigned char *salt, unsigned char result[16])
{
	MD5_CTX context; 

	MD5Init (&context);
    MD5Update (&context, password, 
                          strlen((char *)password));
    MD5Update (&context, salt, strlen((char *)salt));
    MD5Final (result, &context);
}
//用DES加解密
void DES_deal (unsigned char *input, unsigned char *output, 
                          unsigned char *output2,  int len, 
                          unsigned char key[8], unsigned char *iv)
{
   DES_CBC_CTX  context;
   //显示明文
   printf ("plaintext: %s\n", input);
   //加密
   DES_CBCInit(&context, key, iv, 1);
   DES_CBCUpdate(&context, output, input, len);
  //显示密文
   shows (output, len);
   //解密
   DES_CBCInit (&context, key, iv, 0); 
   DES_CBCUpdate(&context, output2, output, len);
  //显示解密后的密文
   printf("decrypted ciphertext: %s\n",output2);     
}
#define SALT_LEN   10    //产生的salt的长度
#define BLOCK_LEN  16  //明密文长度
int main(int argc, char* argv[])
{  
    unsigned char seed[] = "3adqwe1212asd"; // 种子

    unsigned char salt[SALT_LEN];                  // 保存输出的salt

    unsigned char password[10];                      // 口令

    unsigned char mixedresult[16];                   // 保存混合后的结果

    unsigned char key[8];                                  // 用于DES的密钥

    unsigned char iv[8+1] = "abcdfgji";              // IV

    unsigned char input[BLOCK_LEN+1] = "12345678abcdefgh"; // 明文

    unsigned char output[BLOCK_LEN]="", output2[BLOCK_LEN+1]=""; 
create_salt (salt, SALT_LEN, seed);      // 产生salt
    printf ("please input your password:"); 
    scanf ("%s", password);                         // 输入口令

    MixPwdSalt (password, salt, mixedresult);  // 混合salt和口令
    copys (mixedresult, key, 8);

    DES_deal (input, output, output2, BLOCK_LEN, key, iv);   
    
    return 0; 
}
