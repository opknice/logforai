#include <windows.h>
#include <iostream>

int main() {
    // 1. ตรวจสอบ Path ให้ถูกต้อง
    char dllPath[] = "C:\\Users\\User\\Downloads\\sidebyside\\version.dll"; 
    char gamePath[] = "BamBoo_Client.exe";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    // 2. สร้าง Process เกมในสถานะ SUSPENDED
    if (CreateProcessA(NULL, gamePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        
        // 3. จองพื้นที่ในหน่วยความจำของเกม
        LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (remoteMem == NULL) {
            std::cout << "Failed to allocate memory! Error: " << GetLastError() << std::endl;
            TerminateProcess(pi.hProcess, 0);
            return 1;
        }

        // 4. เขียน Path ของ DLL ลงไป
        if (!WriteProcessMemory(pi.hProcess, remoteMem, dllPath, strlen(dllPath) + 1, NULL)) {
            std::cout << "Failed to write memory! Error: " << GetLastError() << std::endl;
            VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            return 1;
        }

        // 5. สั่งให้เกมโหลด DLL ของเรา
        HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), remoteMem, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            std::cout << "DLL Injected successfully!" << std::endl;
            CloseHandle(hThread);
        } else {
            std::cout << "Failed to create remote thread! Error: " << GetLastError() << std::endl;
        }

        // 6. เคลียร์ร่องรอยและเริ่มรันเกม
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        ResumeThread(pi.hThread);
        
        std::cout << "Game resumed!" << std::endl;

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cout << "Failed to start game! Error: " << GetLastError() << std::endl;
    }
    return 0;
}
