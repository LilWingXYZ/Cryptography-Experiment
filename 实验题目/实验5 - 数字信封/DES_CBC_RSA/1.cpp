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

#include <stdio.h>



/*typedef struct PackageCiphertext    //（没有）
{
    unsigned char output[TEXT_LEN]; //密文
	unsigned int  outputlen;        //密文长度
	unsigned char sealedkey[MAX_ENCRYPTED_KEY_LEN]; //封装后的会话密钥
	unsigned int  sealedkeylen; //封装后的会话密钥长度
}PackageCiphertext;*/







// 以十六进制形式显示output中的内容
void shows (unsigned char *output, unsigned int len)
{  printf ("ciphertext: ");
   for (unsigned int i=0; i<len; i++)
	    printf("%x", output[i]);
   printf("\n");
}

//填充随机数结构体            (正确)
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

#define PLAINTEXT_LEN  16  //明文长度

int main(int argc, char* argv[])
{
unsigned char seed[] = "3adqwe1212asd"; // 种子
unsigned char input[PLAINTEXT_LEN+1] = "12345678abcdefgh"; // 明文
unsigned char output[MAX_ENCRYPTED_KEY_LEN]="";
unsigned char output2[PLAINTEXT_LEN+1]="";
unsigned int outputlen, outputlen2;
int flag;

R_RSA_PUBLIC_KEY  publicKey;
R_RSA_PRIVATE_KEY privateKey;
R_RSA_PROTO_KEY   protoKey;
R_RANDOM_STRUCT   randomStruct;

protoKey.bits = 1024;           //设定模数长度为1024
protoKey.useFermat4 = 1;   //设定e=65537
seed_randomStruct (seed, &randomStruct);  // 填充随机数结构体

flag = R_GeneratePEMKeys
         (&publicKey, &privateKey, &protoKey, &randomStruct);   // 产生RSA密钥
    if (RE_MODULUS_LEN == flag)
    {  printf ("modulus length invalid\n");  exit(0); }
    else if (RE_NEED_RANDOM == flag)
    {  printf ("randomStruct is not seeded\n");  exit(0); }
    // 显示明文
    printf ("plaintext: %s\n", input);
    // 加密
   RSAPublicEncrypt (output, &outputlen, input, strlen((char *)input),
		                      &publicKey, &randomStruct);
    // 显示密文
   shows(output, outputlen);
    // 解密
   RSAPrivateDecrypt (output2, &outputlen2, output, outputlen,
                                     &privateKey);
    printf("decrypted ciphertext: %s\n", output2);
    R_RandomFinal (&randomStruct);
    return 0;
}
