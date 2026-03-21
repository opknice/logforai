#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// --- Forwarding ---
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")

typedef int (WSAAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
connect_t pOriginalConnect = NULL;
BYTE origBytes[5];

// --- Memory Helper ---
void Patch(void* dest, void* src, int len) {
    DWORD old;
    VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &old);
    memcpy(dest, src, len);
    VirtualProtect(dest, len, old, &old);
}

// --- Hook Function ---
int WSAAPI MyConnectHook(SOCKET s, const struct sockaddr* name, int namelen) {
    struct sockaddr_in* addr = (struct sockaddr_in*)name;
    unsigned short port = ntohs(addr->sin_port);

    // 🎯 ถ้า Port เกิน 5000 ให้เลี้ยวเข้าบอททันที
    if (port >= 5000) {
        printf("[REDIRECT] Port %d -> 127.0.0.1:6991\n", port);
        addr->sin_addr.s_addr = inet_addr("127.0.0.1");
        addr->sin_port = htons(6991);
    }

    // Unhook ชั่วคราวเพื่อเรียกฟังก์ชันจริง
    Patch(pOriginalConnect, origBytes, 5);
    int res = pOriginalConnect(s, name, namelen);
    
    // Re-hook กลับ
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyConnectHook - (DWORD)pOriginalConnect - 5;
    Patch(pOriginalConnect, jmp, 5);

    return res;
}

void Start() {
    // 💡 รอจนกว่าตัวเกมจะเข้าหน้า Login (เพื่อให้ Gepard คลายการป้องกันบางส่วน)
    Sleep(5000); 
    
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    pOriginalConnect = (connect_t)GetProcAddress(ws2, "connect");

    if (pOriginalConnect) {
        memcpy(origBytes, pOriginalConnect, 5);
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MyConnectHook - (DWORD)pOriginalConnect - 5;
        Patch(pOriginalConnect, jmp, 5);
        printf("[✔] Universal Bridge Active!\n");
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID lp) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Start, 0, 0, 0);
    return 1;
}
