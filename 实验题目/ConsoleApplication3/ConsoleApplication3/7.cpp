#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NN.C"
#include "RSA.C"
#include "DIGIT.C"
#include "MD2C.C"
#include "MD5C.C"
#include "DESC.C"
#include "PRIME.C"
#include "R_STDLIB.C"
#include "R_RANDOM.C"
#include "R_KEYGEN.C"
#include "R_ENHANC.C"
#include "R_ENCODE.C"
#include "R_DH.C"
// 以十六进制形式显示output中的内容
void shows(char *text, unsigned char *output, unsigned int len){
	printf("%s: ", text);
	for (unsigned int i = 0; i<len; i++)
		printf("%x", output[i]);
	printf("\n");
}
//给R_DH_PARAMS的成员分配内存空间
void Init_DH_Params(R_DH_PARAMS *params, unsigned int bits){
	params->prime = new unsigned char[DH_PRIME_LEN(bits)];
	params->generator = new unsigned char[DH_PRIME_LEN(bits)];
}

//销毁分配给R_DH_PARAMS的成员的内存空间
void Destory_DH_Params(R_DH_PARAMS *params){
	delete[]params->prime;
	delete[]params->generator;
}
// 产生DH系统参数
int create_DH_params(R_DH_PARAMS *params, int prime_len, int subprime_len, R_RANDOM_STRUCT *randomStruct){
	// 为DH系统参数成员分配空间
	Init_DH_Params(params, prime_len);

	// 产生DH系统参数
	int ret = R_GenerateDHParams(params, prime_len, subprime_len, randomStruct);

	if (RE_MODULUS_LEN == ret){
		printf("prime length invalid \n"); 
		return 0;
	}
	else if (RE_NEED_RANDOM == ret){
		printf("randomStruct is not seeded \n"); 
		return 0;
	}
	else if (RE_DATA == ret){
		printf("prime bits out of range\n"); 
		return 0;
	}
	return 1;
}
// 产生RSA密钥
int create_RSAkey(char *user, R_RSA_PUBLIC_KEY *publicKey, R_RSA_PRIVATE_KEY *privateKey, unsigned int modul_bits,int useFermat4, R_RANDOM_STRUCT *randomStruct){
	R_RSA_PROTO_KEY   protoKey;
	int flag;

	protoKey.bits = modul_bits;           //设定模数长度
	protoKey.useFermat4 = useFermat4;      //设定e
	flag = R_GeneratePEMKeys(publicKey, privateKey, &protoKey, randomStruct);   // 产生RSA密钥
	if (RE_MODULUS_LEN == flag){
		printf("%s: modulus length invalid\n", user); 
		return 0;
	}
	else if (RE_NEED_RANDOM == flag){
		printf("%s: randomStruct is not seeded\n", user); 
		return 0;
	}
	return 1;
}
// 产生用户的公开值、秘密值
int setup_DH_agreement(char *user, unsigned char *publicValue, unsigned char *privateValue,int privateValueLEN, R_DH_PARAMS *params,R_RANDOM_STRUCT *randomStruct){
	if (RE_NEED_RANDOM == R_SetupDHAgreement(publicValue, privateValue, privateValueLEN, params, randomStruct)){
		printf("%s: randomStruct is not seeded \n", user); 
		return 0;
	}
	return 1;
}
// 产生共享密钥
int create_agreementkey(unsigned char *Key, unsigned char *otherspublicValue, unsigned char *privateValue, int publicValueLen,R_DH_PARAMS *params){
	if (RE_DATA == R_ComputeDHAgreedKey(Key, otherspublicValue, privateValue, publicValueLen, params))
		return 0;
	return 1;
}

// 对公开值计算签名
int  sign(char *user, unsigned char *publicValue, int publicValueLen,unsigned char *signature, unsigned int *signatureLen,R_RSA_PRIVATE_KEY *privateKey){
	R_SIGNATURE_CTX context;

	if (RE_DIGEST_ALGORITHM == R_SignInit(&context, DA_MD5)){
		printf("%s: digestAlgorithm is invalid\n", user);
		return 0;
	}

	R_SignUpdate(&context, publicValue, publicValueLen);

	if (RE_PRIVATE_KEY == R_SignFinal(&context, signature, signatureLen, privateKey)){
		printf("%s: privateKey cannot encrypt message digest\n", user);
		return 0;
	}
	return 1;
}
// 对收到的公开值和签名进行校验
int  verify(char *user, unsigned char *publicValue, int publicValueLen,unsigned char *signature, unsigned int signatureLen,R_RSA_PUBLIC_KEY *publicKey){
	R_SIGNATURE_CTX context;

	if (RE_DIGEST_ALGORITHM == R_VerifyInit(&context, DA_MD5)){
		printf("digestAlgorithm is invalid\n");
		return 0;
	}

	R_VerifyUpdate(&context, publicValue, publicValueLen);

	int ret = R_VerifyFinal(&context, signature, signatureLen, publicKey);
	switch (ret){
	case 0: printf("%s: verify success\n", user); 
		return 1;
	case RE_SIGNATURE: printf("%s: signature is incorrect\n", user); 
		return 0;
	case RE_LEN: printf("%s: signatureLen out of range\n", user); 
		return 0;
	case RE_PUBLIC_KEY: printf("%s: publicKey cannot decrypt signature\n", user); 
		return 0;
	}
	return 0;
}
#define PRIME_BITS         512
#define SUBPRIME_BITS           (PRIME_BITS-10)
#define PRIVATE_VALUE_LEN  DH_PRIME_LEN(SUBPRIME_BITS-1)
#define PUBLIC_VALUE_LEN    DH_PRIME_LEN(PRIME_BITS)

#define LEN  16

int main(){
	R_DH_PARAMS  params;
	unsigned char seed[] = "asdfsafsafs2341131231";
	R_RANDOM_STRUCT randomStruct;

	unsigned char Alice_publicValue[PUBLIC_VALUE_LEN],Bob_publicValue[PUBLIC_VALUE_LEN];
	unsigned char Alice_privateValue[PRIVATE_VALUE_LEN],Bob_privateValue[PRIVATE_VALUE_LEN];
	unsigned char Alice_Key[PUBLIC_VALUE_LEN],Bob_Key[PUBLIC_VALUE_LEN];
	unsigned char Alice_signature[MAX_ENCRYPTED_KEY_LEN],Bob_signature[MAX_ENCRYPTED_KEY_LEN];
	unsigned int Alice_signLen, Bob_signLen;

	R_RSA_PUBLIC_KEY   Alice_publicKey, Bob_publicKey;
	R_RSA_PRIVATE_KEY Alice_privateKey, Bob_privateKey;
	DES_CBC_CTX  context;

	unsigned char input[LEN + 1] = "12345678abcdefgh";
	unsigned char output[LEN];
	unsigned char output2[LEN + 1] = "";
	unsigned char iv[8 + 1] = "1asdf243";

	unsigned int bytesNeeded = 256;  //结构体所需种子长度
	R_RandomInit(&randomStruct);
	while (bytesNeeded > 0){
		R_RandomUpdate(&randomStruct, seed,strlen((char *)seed));
		R_GetRandomBytesNeeded(&bytesNeeded,&randomStruct);
	}

	printf("create DH params...\n");

	if (!create_DH_params(&params, PRIME_BITS,SUBPRIME_BITS, &randomStruct))
		return 1;

	printf("create RSA key...\n");
	// 分别产生Alice、Bob的RSA密钥
	if (!create_RSAkey("Alice", &Alice_publicKey,&Alice_privateKey, 1024, 1, &randomStruct))
		return 0;
	if (!create_RSAkey("Bob", &Bob_publicKey,&Bob_privateKey, 1024, 1, &randomStruct))
		return 0;

	printf("setup DH agreement...\n");
	// 分别产生Alice、Bob的DH公开值、秘密值
	if (!setup_DH_agreement("Alice", Alice_publicValue, Alice_privateValue,PRIVATE_VALUE_LEN, &params, &randomStruct))
		return 0;
	if (!setup_DH_agreement("Bob", Bob_publicValue, Bob_privateValue,PRIVATE_VALUE_LEN, &params, &randomStruct))
		return 0;

	printf("sign DH public value...\n");
	//分别对自己的公开值进行签名
	if (!sign("Alice", Alice_publicValue,PUBLIC_VALUE_LEN, Alice_signature,&Alice_signLen, &Alice_privateKey))
		return 0;
	if (!sign("Bob", Bob_publicValue,PUBLIC_VALUE_LEN, Bob_signature,&Bob_signLen, &Bob_privateKey))
		return 0;
	printf("\nsending to each other.\n\n");

	printf("verify DH public value...\n");
	// 分别校验收到的公开值和签名的有效性(是否在传输时被篡改)
	if (!verify("Alice", Bob_publicValue,PUBLIC_VALUE_LEN, Bob_signature,Bob_signLen, &Bob_publicKey))
		return 0;
	if (!verify("Bob", Alice_publicValue,PUBLIC_VALUE_LEN, Alice_signature,Alice_signLen, &Alice_publicKey))
		return 0;
	printf("create agreement key...\n");
	//分别计算Alice、Bob的共享密钥	
	if (!create_agreementkey(Alice_Key, Bob_publicValue, Alice_privateValue, PRIVATE_VALUE_LEN, &params)){
		printf("Bob's public value out of range \n"); 
		return 0;
	}
	if (!create_agreementkey(Bob_Key, Alice_publicValue, Bob_privateValue, PRIVATE_VALUE_LEN, &params)){
		printf("Alice's public value out of range \n"); 
		return 0;
	}

	shows("Alice's key", Alice_Key,	DH_PRIME_LEN(PRIME_BITS));
	shows("Bob's key", Bob_Key,	DH_PRIME_LEN(PRIME_BITS));
	printf("Alice's plaintext: %s\n", input);
	printf("Alice encrypts plaintext with Alice_Key...\n");
	// Alice加密明文
	DES_CBCInit(&context, Alice_Key, iv, 1);
	DES_CBCUpdate(&context, output, input, LEN);

	shows("Alice creates ciphertext with Alice_Key", output, LEN);

	printf("\nAlice sends ciphertext to Bob.\n\n");

	printf("Bob decrypts ciphertex with Bob_Key...\n");
	// Bob解密密文
	DES_CBCInit(&context, Bob_Key, iv, 0);
	DES_CBCUpdate(&context, output2, output, LEN);

	printf("decrypted ciphertext: %s\n", output2);

	Destory_DH_Params(&params);
	R_RandomFinal(&randomStruct);

	return 0;
}
