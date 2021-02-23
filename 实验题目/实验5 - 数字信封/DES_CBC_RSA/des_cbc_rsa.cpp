#include <string.h>
#include <stdlib.h>
#include "R_STDLIB.C"
#include "R_RANDOM.C"
#include "NN.C"
#include "RSA.C"
#include "DIGIT.C"
#include "MD5C.C"
#include "PRIME.C"
#include "R_KEYGEN.C"
#include "DESC.C"
#include <stdio.h>

#define TEXT_LEN  16  //明密文长度

struct SealCipherText
{
	unsigned char output[TEXT_LEN]; //密文
	unsigned int  outputlen;        //密文长度
	unsigned char sealedkey[MAX_ENCRYPTED_KEY_LEN]; //封装后的会话密钥
    unsigned int  sealedkeylen; //封装后的会话密钥长度
};

// 以十六进制形式显示output中的内容
void shows (char *msg, unsigned char *output, unsigned int len)
{  printf ("%s: ", msg);
   for (unsigned int i=0; i<len; i++)
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
	   R_GetRandomBytesNeeded (&bytesNeeded, randomStruct);
	}
}

//产生RSA密钥
void create_RSAkey (R_RSA_PUBLIC_KEY *publicKey, R_RSA_PRIVATE_KEY *privateKey,  unsigned int modul_bits,
     int useFermat4, R_RANDOM_STRUCT *randomStruct)
{
   R_RSA_PROTO_KEY   protoKey;
   int flag;

   protoKey.bits = modul_bits;           //设定模数长度
   protoKey.useFermat4 = useFermat4;      //设定e

   flag = R_GeneratePEMKeys 
         (publicKey, privateKey, &protoKey, randomStruct);   // 产生RSA密钥


    if (RE_MODULUS_LEN == flag)
    {  printf ("modulus length invalid\n");  exit(0); }
    else if (RE_NEED_RANDOM == flag)
    {  printf ("randomStruct is not seeded\n");  exit(0); }
}

//数字信封封装(加密)
void SealEnc  (SealCipherText *sealedtext,
	unsigned char *input, int inputlen, R_RSA_PUBLIC_KEY  *publicKey, 
      unsigned char iv[8], R_RANDOM_STRUCT *randomStruct)
{
   unsigned char key[8] = "";              // 对称会话密钥
   DES_CBC_CTX  context;

   R_GenerateBytes (key, 8, randomStruct); //产生随机对称会话密钥

   // 加密明文
   DES_CBCInit(&context, key, iv, 1);
   DES_CBCUpdate(&context, sealedtext->output, input, inputlen);

   sealedtext->outputlen = inputlen;

   // 加密key
   RSAPublicEncrypt (sealedtext->sealedkey, &(sealedtext->sealedkeylen), key, 8, publicKey, randomStruct);
}

//数字信封解封(解密)
void SealDec  (unsigned char *output2, SealCipherText *sealedtext,
               R_RSA_PRIVATE_KEY  *privateKey, unsigned char iv[8])
{
   DES_CBC_CTX  context;
   unsigned char key[8];
   unsigned int keylen;

   //恢复key
   RSAPrivateDecrypt (key, &keylen, sealedtext->sealedkey, sealedtext->sealedkeylen, privateKey);

   //解密密文
   DES_CBCInit (&context, key, iv, 0); 
   DES_CBCUpdate(&context, output2, sealedtext->output, sealedtext->outputlen);
}

int main(int argc, char* argv[])
{  
unsigned char seed[] = "3adqwe1212asd"; // 种子
unsigned char iv[8+1] = "13wedfgr";     // IV
unsigned char input[TEXT_LEN+1] = "12345678abcdefgh"; // 明文
unsigned char output2[TEXT_LEN+1] = ""; // 恢复的明文

SealCipherText sealedtext; 
	
R_RSA_PUBLIC_KEY  publicKey;
R_RSA_PRIVATE_KEY privateKey; 
R_RANDOM_STRUCT   randomStruct;

// 显示明文
printf ("plaintext: %s\n", input);

seed_randomStruct (seed, &randomStruct);  // 填充随机数结构体
create_RSAkey (&publicKey, &privateKey, 1024, 1, &randomStruct); //产生RSA公钥

// 数字信封封装(加密)
SealEnc (&sealedtext, input, TEXT_LEN, &publicKey, iv, &randomStruct);

// 显示密文和封装后的会话密钥
shows("ciphertext", sealedtext.output, TEXT_LEN);
shows("sealed key", sealedtext.sealedkey, sealedtext.sealedkeylen);

// 数字信封解封(解密)
SealDec (output2, &sealedtext, &privateKey, iv);

// 显示恢复出的明文
printf("decrypted ciphertext: %s\n", output2);

R_RandomFinal (&randomStruct);

return 0; 
}

