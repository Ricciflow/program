#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

// AES加密函数

std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[plaintext_len + EVP_MAX_BLOCK_LENGTH]);

if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}

int len;
if (!EVP_EncryptUpdate(ctx, ciphertext.get(), &len, plaintext, plaintext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}
*ciphertext_len = len;

if (!EVP_EncryptFinal_ex(ctx, ciphertext.get() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}
*ciphertext_len += len;

EVP_CIPHER_CTX_free(ctx);
return ciphertext;


// AES解密函数
std::unique_ptr<unsigned char[]> aes_decrypt(const unsigned char* ciphertext, int ciphertext_len,
const unsigned char* key, const unsigned char* iv,
int* plaintext_len)
{
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
if (!ctx) {
return nullptr;
}


std::unique_ptr<unsigned char[]> plaintext(new unsigned char[ciphertext_len]);

if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}

int len;
if (!EVP_DecryptUpdate(ctx, plaintext.get(), &len, ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}
*plaintext_len = len;

if (!EVP_DecryptFinal_ex(ctx, plaintext.get() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return nullptr;
}
*plaintext_len += len;

EVP_CIPHER_CTX_free(ctx);
return plaintext;


int main()
{
// 加密参数
unsigned char key[] = "12345678901234567890123456789012";
unsigned char iv[] = "1234567890123456";
// shellcode
unsigned char plaintext[] = "\xfc...";
int plaintext_len = sizeof plaintext - 1;

// 执行加密操作
int ciphertext_len;
auto ciphertext = aes_encrypt(plaintext, plaintext_len, key, iv, &ciphertext_len);
if (!ciphertext) {
    printf("Encryption failed\n");
    return 1;
}

// 输出加密结果
printf("ciphertext = ");
for (int i = 0; i < ciphertext_len; i++) {
    printf("\\x%02x", ciphertext[i]);
}
printf("\n");

// 执行解密操作
int decrypted_len;
auto decrypted = aes_decrypt(ciphertext.get(), ciphertext_len, key, iv, &decrypted_len);
if (!decrypted) {
    printf("Decryption failed\n");
    return 1;
}

// 输出解密结果
printf("decrypted = ");
for (int i = 0; i < decrypted_len; i++) {
    printf("%c", decrypted[i]);
}
printf("\n");

return 0;

}
