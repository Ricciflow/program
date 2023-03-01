#include <iostream>

using namespace std;

unsigned char* encrypt(unsigned char* input, int len, unsigned int key) {
    unsigned char* output = new unsigned char[len];
    srand(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ key;
        output[i] = output[i] ^ (rand() % len + 1);
    }
    return output;
}

unsigned char* decrypt(unsigned char* input, int len, unsigned int key) {
    unsigned char* output = new unsigned char[len];
    srand(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ (rand() % len + 1);
        output[i] = output[i] ^ key;
    }
    return output;
}

int main() {
    // 加密前的shellcode
    unsigned char input[] = "\xfc...";
    // 6位数的密钥
    unsigned int key = 454545;
    int len = sizeof input - 1;

    cout << "Original message: " << input << endl;

    unsigned char* encrypted = encrypt(input, len, key);
    cout << "Encrypted message: ";
    for (int i = 0; i < len; i++)
        printf("\\x%x", encrypted[i]);
    cout << endl;

    unsigned char* decrypted = decrypt(encrypted, len, key);
    cout << "Decrypted message: ";
    for (int i = 0; i < len; i++)
        printf("%c", decrypted[i]);

    delete[] encrypted;
    delete[] decrypted;

    return 0;
}
