/*
说明：

1、功能：
该程序依次进行“签名->加密->解密->认证”
          输入文件        |        输出文件
签名      file.pdf        |        signature
加密 	  file.pdf   	  |        encrypted
解密	  encrypted       |        file.pdf
认证  signature+file.pdf  |            /

2、算法：
加密函数和解密函数使用的是DES算法
签名函数和认证函数使用的是RSA算法

3、使用:
(1) file.pdf作为整个程序的输入文件，需要和本源文件src.c放在同一目录下，或者修改宏定义部分file.pdf的路径。
(2) 输出文件都输出在与本源文件src.c同一目录下，如需指定输出目录，修改宏定义部分file.pdf的路径。
(3) 加密与解密在实际应用中是在通信双方分别完成的，但本程序模拟均在同一目录下执行，且加密前文件与解密后文件同名，故会发生覆盖。
    如有需要可修改宏定义部分文件名或文件路径。

4、其他：
正常的签名是加在原文件后面的，因为老师要求要有一个"signature"文件，该程序就把签名单独输出来了。
*/

//头文件声明
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/applink.c>

//链接动态库
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

//文件路径定义
#define INPUT_FILE_PATH "file.pdf"
#define OUTPUT_FILE_PATH "file.pdf"
#define OUTPUT_MIWEN_PATH "encrypted"
#define OUTPUT_SIGN_PATH "signature"

//全局变量声明
//unsigned char key[EVP_MAX_KEY_LENGTH];  //保存密钥的数组
//unsigned char iv[EVP_MAX_KEY_LENGTH];   //保存初始化向量的数组


//主函数
int main()
{
	struct rsa_st *keySign,*pubSign, *priSign;

	//函数声明
	int Sign_File(RSA *priSign);
	int Verify_File(RSA *pubSign);
	int Encrypt_File();
	int Decrypt_File();
	OpenSSL_add_all_algorithms();

	//生成一对用于签名的RSA密钥
	keySign = RSA_generate_key(512, 3, NULL, NULL);
	pubSign = RSAPublicKey_dup(keySign);
	priSign = RSAPrivateKey_dup(keySign);

	//依次进行签名->加密->解密->认证
	Sign_File(keySign);
	Encrypt_File();
	Decrypt_File();
	Verify_File(keySign);

	return 0;
}

int Sign_File(RSA *priSign)
{
	unsigned char sig_buf[4096]; //签名缓冲区
	unsigned int sig_len; //签名缓冲区大小
	int err,filesize;
	char* data;
	EVP_MD_CTX md_ctx;
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	printf("Signature begins.\n");
	ERR_load_crypto_strings();

	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, priSign); //RSA私钥格式转换

	if (pkey == NULL) {
		printf("pkey == NULL\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	fp = fopen(INPUT_FILE_PATH, "rb"); 
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	data = (char*)malloc(sizeof(char)*filesize);
	fseek(fp, 0, SEEK_SET);
	fread(data, filesize, sizeof(char), fp); //读入待签名文件
	fclose(fp);

	EVP_SignInit(&md_ctx, EVP_sha1()); //初始化
	EVP_SignUpdate(&md_ctx, data, strlen(data)); //信息摘要
	sig_len = sizeof(sig_buf);
	err = EVP_SignFinal(&md_ctx, sig_buf, &sig_len, pkey); //签名

	if (err != 1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	EVP_PKEY_free(pkey);
	fp = fopen(OUTPUT_SIGN_PATH, "wb");
	fwrite(sig_buf, 1, sig_len, fp); //将签名写入文件
	fclose(fp);

	printf("Signature done.\n");
	return 1;
}

int Verify_File(RSA *pubSign)
{
	unsigned char *sig_buf; //签名缓冲区
	unsigned int sig_len; //签名缓冲区大小
	int err,filesize;
	char* data;
	EVP_MD_CTX md_ctx;
	EVP_PKEY *pkey = NULL;
	FILE *fp;
	X509 *x509;

	printf("Verification begins.\n");
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, pubSign);  //RSA公钥格式转换

	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	fp = fopen(INPUT_FILE_PATH, "rb");
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	data = (char*)malloc(sizeof(char)*filesize);
	fseek(fp, 0, SEEK_SET);
	fread(data, filesize, sizeof(char), fp); //读入待认证文件
	fclose(fp);

	fp = fopen(OUTPUT_SIGN_PATH, "rb");
	fseek(fp, 0, SEEK_END);
	sig_len = ftell(fp);
	sig_buf = (unsigned char*)malloc(sizeof(unsigned char)*sig_len);
	fseek(fp, 0, SEEK_SET);
	fread(sig_buf, sig_len, sizeof(char), fp); //读入签名
	fclose(fp);

	EVP_VerifyInit(&md_ctx, EVP_sha1()); //初始化
	EVP_VerifyUpdate(&md_ctx, data, strlen((char *)data)); //原文件信息摘要
	err = EVP_VerifyFinal(&md_ctx, sig_buf, sig_len, pkey); //认证

	EVP_PKEY_free(pkey);

	if (err != 1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	printf("Verification done.\n");
	return 1;
}

//加密函数
int  Encrypt_File()
{
    unsigned char key[EVP_MAX_KEY_LENGTH];  //密钥
    unsigned char iv[EVP_MAX_KEY_LENGTH];   //初始化向量
    EVP_CIPHER_CTX ctx; 
    unsigned char out[1024];        //密文缓冲区
    unsigned char in[1024];         //原文缓冲区
    int outflag,inflag,rv,i;
    FILE *fpIn,*fpOut;

	printf("Encryption begins.\n");

    fpIn = fopen(INPUT_FILE_PATH,"rb");
    if(fpIn==NULL)
    {
        return -1;
    }

    fpOut = fopen(OUTPUT_MIWEN_PATH,"wb");
    if(fpOut==NULL)
    {
        fclose(fpIn);
        return -1;
    }
    
    for(i=0;i<24;i++)
    {
        key[i]=i;
    }
    for(i=0;i<8;i++)
    {
        iv[i]=i;
    }

    EVP_CIPHER_CTX_init(&ctx); 
    
	//开始加密，以上为加密前准备工作
    rv = EVP_EncryptInit_ex(&ctx,EVP_des_ede3_cbc(),NULL,key,iv);
    if(rv != 1)
    {
        printf("Err\n");
        return -1;
    }
    
    for(;;)
    {
        inflag = fread(in,1,1024,fpIn); //分段读取原文
        if(inflag <= 0) //剩余原文不足长时结束循环
            break;
        rv = EVP_EncryptUpdate(&ctx,out,&outflag,in,inflag);//加密
        if(rv != 1)
        {
            fclose(fpIn);
            fclose(fpOut);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return -1;
        }
        fwrite(out,1,outflag,fpOut);  //输出密文
    }
    rv = EVP_EncryptFinal_ex(&ctx,out,&outflag); //处理残余原文
    if(rv != 1)
    {
        fclose(fpIn);
        fclose(fpOut);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    fwrite(out,1,outflag,fpOut); 
    fclose(fpIn);
    fclose(fpOut);
    EVP_CIPHER_CTX_cleanup(&ctx); 
	//结束加密

	printf("Encryption done.\n");
    return 1;
}

//解密函数
int Decrypt_File()
{
    unsigned char key[EVP_MAX_KEY_LENGTH];      //密钥
    unsigned char iv[EVP_MAX_KEY_LENGTH];       //初始化向量
    EVP_CIPHER_CTX ctx;  
    unsigned char out[1024+EVP_MAX_KEY_LENGTH]; //明文缓冲区
    unsigned char in[1024];             //密文缓冲区
    int outflag, inflag, rv, i;
    FILE *fpIn,*fpOut;

	printf("Decryption begins.\n");
    
    fpIn = fopen(OUTPUT_MIWEN_PATH,"rb");
    if(fpIn==NULL)
    {
        return -1;
    }
    
    fpOut = fopen(OUTPUT_FILE_PATH,"wb");
    if(fpOut==NULL)
    {
        fclose(fpIn);
        return -1;
    }
    
    for(i=0;i<24;i++)
    {
        key[i]=i;
    }
    for(i=0;i<8;i++)
    {
        iv[i]=i;
    }
   
    EVP_CIPHER_CTX_init(&ctx);
    
	//开始解密，以上为解密前准备工作
    rv = EVP_DecryptInit_ex(&ctx,EVP_des_ede3_cbc(),NULL,key,iv);
    if(rv != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    
    for(;;) 
    {
        inflag = fread(in,1,1024,fpIn); //分段读取原文
        if(inflag <= 0) //剩余原文不足长时结束循环
            break;
        rv = EVP_DecryptUpdate(&ctx,out,&outflag,in,inflag); //解密
        if(rv != 1)
        {
            fclose(fpIn);
            fclose(fpOut);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return -1;
        }
        fwrite(out,1,outflag,fpOut); //输出明文
    }
    
    rv = EVP_DecryptFinal_ex(&ctx,out,&outflag); //处理残余密文
    if(rv != 1)
    {
        fclose(fpIn);
        fclose(fpOut);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    fwrite(out,1,outflag,fpOut);
    fclose(fpIn);
    fclose(fpOut);
    EVP_CIPHER_CTX_cleanup(&ctx);
	//解密结束

	printf("Decryption done.\n");
    return 1;
}

