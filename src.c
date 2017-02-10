/*
˵����

1�����ܣ�
�ó������ν��С�ǩ��->����->����->��֤��
          �����ļ�        |        ����ļ�
ǩ��      file.pdf        |        signature
���� 	  file.pdf   	  |        encrypted
����	  encrypted       |        file.pdf
��֤  signature+file.pdf  |            /

2���㷨��
���ܺ����ͽ��ܺ���ʹ�õ���DES�㷨
ǩ����������֤����ʹ�õ���RSA�㷨

3��ʹ��:
(1) file.pdf��Ϊ��������������ļ�����Ҫ�ͱ�Դ�ļ�src.c����ͬһĿ¼�£������޸ĺ궨�岿��file.pdf��·����
(2) ����ļ���������뱾Դ�ļ�src.cͬһĿ¼�£�����ָ�����Ŀ¼���޸ĺ궨�岿��file.pdf��·����
(3) �����������ʵ��Ӧ��������ͨ��˫���ֱ���ɵģ���������ģ�����ͬһĿ¼��ִ�У��Ҽ���ǰ�ļ�����ܺ��ļ�ͬ�����ʻᷢ�����ǡ�
    ������Ҫ���޸ĺ궨�岿���ļ������ļ�·����

4��������
������ǩ���Ǽ���ԭ�ļ�����ģ���Ϊ��ʦҪ��Ҫ��һ��"signature"�ļ����ó���Ͱ�ǩ������������ˡ�
*/

//ͷ�ļ�����
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

//���Ӷ�̬��
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

//�ļ�·������
#define INPUT_FILE_PATH "file.pdf"
#define OUTPUT_FILE_PATH "file.pdf"
#define OUTPUT_MIWEN_PATH "encrypted"
#define OUTPUT_SIGN_PATH "signature"

//ȫ�ֱ�������
//unsigned char key[EVP_MAX_KEY_LENGTH];  //������Կ������
//unsigned char iv[EVP_MAX_KEY_LENGTH];   //�����ʼ������������


//������
int main()
{
	struct rsa_st *keySign,*pubSign, *priSign;

	//��������
	int Sign_File(RSA *priSign);
	int Verify_File(RSA *pubSign);
	int Encrypt_File();
	int Decrypt_File();
	OpenSSL_add_all_algorithms();

	//����һ������ǩ����RSA��Կ
	keySign = RSA_generate_key(512, 3, NULL, NULL);
	pubSign = RSAPublicKey_dup(keySign);
	priSign = RSAPrivateKey_dup(keySign);

	//���ν���ǩ��->����->����->��֤
	Sign_File(keySign);
	Encrypt_File();
	Decrypt_File();
	Verify_File(keySign);

	return 0;
}

int Sign_File(RSA *priSign)
{
	unsigned char sig_buf[4096]; //ǩ��������
	unsigned int sig_len; //ǩ����������С
	int err,filesize;
	char* data;
	EVP_MD_CTX md_ctx;
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	printf("Signature begins.\n");
	ERR_load_crypto_strings();

	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, priSign); //RSA˽Կ��ʽת��

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
	fread(data, filesize, sizeof(char), fp); //�����ǩ���ļ�
	fclose(fp);

	EVP_SignInit(&md_ctx, EVP_sha1()); //��ʼ��
	EVP_SignUpdate(&md_ctx, data, strlen(data)); //��ϢժҪ
	sig_len = sizeof(sig_buf);
	err = EVP_SignFinal(&md_ctx, sig_buf, &sig_len, pkey); //ǩ��

	if (err != 1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	EVP_PKEY_free(pkey);
	fp = fopen(OUTPUT_SIGN_PATH, "wb");
	fwrite(sig_buf, 1, sig_len, fp); //��ǩ��д���ļ�
	fclose(fp);

	printf("Signature done.\n");
	return 1;
}

int Verify_File(RSA *pubSign)
{
	unsigned char *sig_buf; //ǩ��������
	unsigned int sig_len; //ǩ����������С
	int err,filesize;
	char* data;
	EVP_MD_CTX md_ctx;
	EVP_PKEY *pkey = NULL;
	FILE *fp;
	X509 *x509;

	printf("Verification begins.\n");
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, pubSign);  //RSA��Կ��ʽת��

	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	fp = fopen(INPUT_FILE_PATH, "rb");
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	data = (char*)malloc(sizeof(char)*filesize);
	fseek(fp, 0, SEEK_SET);
	fread(data, filesize, sizeof(char), fp); //�������֤�ļ�
	fclose(fp);

	fp = fopen(OUTPUT_SIGN_PATH, "rb");
	fseek(fp, 0, SEEK_END);
	sig_len = ftell(fp);
	sig_buf = (unsigned char*)malloc(sizeof(unsigned char)*sig_len);
	fseek(fp, 0, SEEK_SET);
	fread(sig_buf, sig_len, sizeof(char), fp); //����ǩ��
	fclose(fp);

	EVP_VerifyInit(&md_ctx, EVP_sha1()); //��ʼ��
	EVP_VerifyUpdate(&md_ctx, data, strlen((char *)data)); //ԭ�ļ���ϢժҪ
	err = EVP_VerifyFinal(&md_ctx, sig_buf, sig_len, pkey); //��֤

	EVP_PKEY_free(pkey);

	if (err != 1) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	printf("Verification done.\n");
	return 1;
}

//���ܺ���
int  Encrypt_File()
{
    unsigned char key[EVP_MAX_KEY_LENGTH];  //��Կ
    unsigned char iv[EVP_MAX_KEY_LENGTH];   //��ʼ������
    EVP_CIPHER_CTX ctx; 
    unsigned char out[1024];        //���Ļ�����
    unsigned char in[1024];         //ԭ�Ļ�����
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
    
	//��ʼ���ܣ�����Ϊ����ǰ׼������
    rv = EVP_EncryptInit_ex(&ctx,EVP_des_ede3_cbc(),NULL,key,iv);
    if(rv != 1)
    {
        printf("Err\n");
        return -1;
    }
    
    for(;;)
    {
        inflag = fread(in,1,1024,fpIn); //�ֶζ�ȡԭ��
        if(inflag <= 0) //ʣ��ԭ�Ĳ��㳤ʱ����ѭ��
            break;
        rv = EVP_EncryptUpdate(&ctx,out,&outflag,in,inflag);//����
        if(rv != 1)
        {
            fclose(fpIn);
            fclose(fpOut);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return -1;
        }
        fwrite(out,1,outflag,fpOut);  //�������
    }
    rv = EVP_EncryptFinal_ex(&ctx,out,&outflag); //�������ԭ��
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
	//��������

	printf("Encryption done.\n");
    return 1;
}

//���ܺ���
int Decrypt_File()
{
    unsigned char key[EVP_MAX_KEY_LENGTH];      //��Կ
    unsigned char iv[EVP_MAX_KEY_LENGTH];       //��ʼ������
    EVP_CIPHER_CTX ctx;  
    unsigned char out[1024+EVP_MAX_KEY_LENGTH]; //���Ļ�����
    unsigned char in[1024];             //���Ļ�����
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
    
	//��ʼ���ܣ�����Ϊ����ǰ׼������
    rv = EVP_DecryptInit_ex(&ctx,EVP_des_ede3_cbc(),NULL,key,iv);
    if(rv != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    
    for(;;) 
    {
        inflag = fread(in,1,1024,fpIn); //�ֶζ�ȡԭ��
        if(inflag <= 0) //ʣ��ԭ�Ĳ��㳤ʱ����ѭ��
            break;
        rv = EVP_DecryptUpdate(&ctx,out,&outflag,in,inflag); //����
        if(rv != 1)
        {
            fclose(fpIn);
            fclose(fpOut);
            EVP_CIPHER_CTX_cleanup(&ctx);
            return -1;
        }
        fwrite(out,1,outflag,fpOut); //�������
    }
    
    rv = EVP_DecryptFinal_ex(&ctx,out,&outflag); //�����������
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
	//���ܽ���

	printf("Decryption done.\n");
    return 1;
}

