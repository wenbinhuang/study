/* copy from openssl 1.1.1 and modify for win10 vs2019 by huangwenbin */

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/applink.c>


/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f, 0x00, 0x00, 0x00, 0x00
};

static unsigned char gcm_pt[] = {
    'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '.', 'a', 'b', 'c'
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84, 0x00, 0x00, 0x00, 0x00
};

static unsigned char gcm_ct[sizeof(gcm_pt)] = {
};

static unsigned char gcm_tag[16] = {
};

static unsigned char gcm_output[sizeof(gcm_pt)] = {
};


void aes_gcm_encrypt(const unsigned char* pt, const int pt_sz, const unsigned char* key, const int key_sz, const unsigned char* iv, const int iv_sz,
                           unsigned char* out, int out_sz, unsigned char* tag, int tag_sz)
{
    EVP_CIPHER_CTX* ctx;
    printf("AES GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, (const char*)pt, pt_sz);
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, key_sz, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_sz, NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, out, &out_sz, pt, pt_sz);

    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, (const char*)out, out_sz);
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, out, &out_sz);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_sz, tag);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, (const char*)tag, tag_sz);
    EVP_CIPHER_CTX_free(ctx);
}


void aes_gcm_decrypt(const unsigned char* ct, const int ct_sz, const unsigned char* key, const int key_sz, const unsigned char* iv, const int iv_sz,
                     const unsigned char* tag, const int tag_sz, unsigned char* out, int out_sz)
{
    EVP_CIPHER_CTX* ctx;
    int rv;

    printf("AES GCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, (const char*)ct, ct_sz);
    ctx = EVP_CIPHER_CTX_new();
    /* Select cipher */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    /* Set IV length, omit for 96 bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, key_sz, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_sz, NULL);
    /* Specify key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    /* Decrypt plaintext */
    EVP_DecryptUpdate(ctx, out, &out_sz, ct, ct_sz);
    /* Output decrypted block */
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, (const char*)out, out_sz);
    /* Set expected tag value. */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_sz, (void*)tag);
    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, out, &out_sz);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
    EVP_CIPHER_CTX_free(ctx);
}


int main(void)
{
    aes_gcm_encrypt(gcm_pt, sizeof(gcm_ct), gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv), gcm_ct, sizeof(gcm_ct), gcm_tag, sizeof(gcm_tag));
    aes_gcm_decrypt(gcm_ct, sizeof(gcm_ct), gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv), gcm_tag, sizeof(gcm_tag), gcm_ct, sizeof(gcm_ct));
}
