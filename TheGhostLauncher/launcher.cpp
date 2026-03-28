#include <windows.h>
#include <iostream>

int main() {
    char dllPath[] = "D:\\logforai\\openkore-master\\version.dll"; // Path ของ DLL เราข้างนอกเกม
    char gamePath[] = "Rag.exe";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA(gamePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(pi.hProcess, remoteMem, dllPath, strlen(dllPath) + 1, NULL);

        HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMem, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            std::cout << "DLL Injected successfully into memory!" << std::endl;
            CloseHandle(hThread);
        }

        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE); // ลบ Path ออกจาก Memory ของเกมทันที
        ResumeThread(pi.hThread);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cout << "Failed to start game! Error: " << GetLastError() << std::endl;
    }
    return 0;
}
