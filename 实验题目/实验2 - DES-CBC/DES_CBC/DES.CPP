#include <string.h>
#include "R_STDLIB.C"
#include "DESC.C"
#include <stdio.h>

//以十六进制形式显示output中的内容
void shows (unsigned char *output, int len)
{  printf ("ciphertext: ");
   for (int i=0; i<len; i++)
	   printf("%x", output[i]);
   printf("\n");
}
 #define LEN 16  //明文长度

int main(int argc, char* argv[])
{  
    DES_CBC_CTX  context;
    //明文串input、密文串output、解密后的明文串output2
	unsigned char input[LEN+1] = "12345678abcdefgh",  output[LEN]="", output2[LEN+1]="";

    //密钥key,初始向量iv
	unsigned char key[8+1] = "qwertyui", iv[8+1] = "abcdfgji";
     //显示明文
      printf("plaintext: %s\n", input);
	 //加密
 	 DES_CBCInit(&context, key, iv, 1);
      DES_CBCUpdate(&context, output, input, LEN);
      //显示密文
      shows (output, LEN);
     //解密
     DES_CBCInit (&context, key, iv, 0); 
     DES_CBCUpdate(&context, output2, output, LEN);
     //显示解密后的密文
     printf("decrypted ciphertext: %s\n",output2);     
    return 0; 
}
