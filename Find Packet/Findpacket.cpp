#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>
#include <intrin.h>
#include <unordered_map>
#include <string>

#pragma intrinsic(_ReturnAddress)
#pragma comment(lib, "ws2_32.lib")

// ============================================================
//  Type Definitions
// ============================================================
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;
recv_t pOriginalRecv = NULL;
BYTE origSendBytes[5], origRecvBytes[5];

static FILE* gConOut = NULL; // stdout ที่ redirect ไป CONOUT$
static std::unordered_map<unsigned short, std::string> gOpNameMap;
static bool gOpMapLoaded = false; // กันไม่ให้โหลดซ้ำ
static HMODULE gSelfModule = nullptr; // เก็บ handle ของ DLL เพื่อหา path ตัวเอง

// ============================================================
//  OpCode Table (Ragnarök Online)
// ============================================================
// --- Helper: แปลง OpCode เป็นข้อความ ---
const char* GetOpName(unsigned short opcode) {
    // ถ้า map ยังไม่ถูก load (ไม่ควรเกิด แต่ป้องกันไว้)
    if (!gOpMapLoaded) return "MAP_NOT_LOADED";

    auto it = gOpNameMap.find(opcode);
    if (it != gOpNameMap.end()) {
        return it->second.c_str(); // คืน pointer ของ string ใน map
    }
    return "UNKNOWN";
}

// ============================================================
//  InitConsole
//  AllocConsole() สร้างหน้าต่าง Console ใหม่แยกจาก process หลัก
//  จากนั้น freopen_s redirect stdout → CONOUT$ เพื่อให้ printf ทำงานได้
// ============================================================
void InitConsole() {
    AllocConsole();
    SetConsoleTitleA("[HyBridge] RO Packet Monitor");

    // ขยาย buffer ให้รองรับ packet จำนวนมากโดยไม่ scroll หาย
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD bufSize = { 200, 5000 };
    SetConsoleScreenBufferSize(hCon, bufSize);

    // เปิด ANSI color escape code (Windows 10 v1511+)
    DWORD mode = 0;
    GetConsoleMode(hCon, &mode);
    SetConsoleMode(hCon, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Redirect stdout ไปหา Console จริง ๆ
    freopen_s(&gConOut, "CONOUT$", "w", stdout);

    printf("==========================================================\n");
    printf("  HyBridge :: Ragnarok Online Packet Monitor\n");
    printf("  \033[36m[C->S]\033[0m = Client to Server"
           "   \033[33m[S->C]\033[0m = Server to Client\n");
    printf("==========================================================\n\n");
}


// ============================================================
//  FormatTimestamp — เขียน HH:MM:SS ลง buffer ที่ส่งเข้ามา
// ============================================================
static void FormatTimestamp(char* out, size_t sz) {
    time_t now = time(0);
    struct tm ltm;
    localtime_s(&ltm, &now);
    sprintf_s(out, sz, "%02d:%02d:%02d",
              ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
}

// LoadOpCodeMap — อ่านไฟล์ packetdescriptions.txt
// แล้วเติมข้อมูลลง gOpNameMap
// pathHint คือ path ของ DLL เองเพื่อค้นหาไฟล์ในโฟลเดอร์เดียวกัน
static void LoadOpCodeMap(const char* dllPath) {
    if (gOpMapLoaded) return; // โหลดครั้งเดียวพอ

    // สร้าง path ของ txt จาก path ของ DLL
    // เช่น "C:\game\HyBridge.dll" → "C:\game\packetdescriptions.txt"
    char txtPath[MAX_PATH] = {};
    strncpy_s(txtPath, dllPath, MAX_PATH);

    // หา backslash ตัวสุดท้าย แล้วต่อชื่อไฟล์เข้าไป
    char* lastSlash = strrchr(txtPath, '\\');
    if (!lastSlash) lastSlash = strrchr(txtPath, '/');

    if (lastSlash) {
        // เขียนทับส่วนหลัง slash ด้วยชื่อไฟล์ที่ต้องการ
        strcpy_s(lastSlash + 1, MAX_PATH - (lastSlash - txtPath) - 1,
                 "packetdescriptions.txt");
    } else {
        // กรณีไม่มี path (ไม่น่าเกิด) ใช้ชื่อไฟล์ตรง ๆ
        strcpy_s(txtPath, "packetdescriptions.txt");
    }

    FILE* f = nullptr;
    if (fopen_s(&f, txtPath, "r") != 0) {
        printf("[!] Cannot open: %s\n", txtPath);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // ตัด newline ออก
        line[strcspn(line, "\r\n")] = '\0';

        // ข้ามบรรทัดว่าง และ header [Recv] / [Send]
        if (line[0] == '\0' || line[0] == '[') continue;

        // parse: "HHHH Description text here"
        // sscanf_s อ่าน hex 4 หลัก แล้วส่วนที่เหลือคือชื่อ
        unsigned int opRaw = 0;
        int charsRead = 0;
        if (sscanf_s(line, "%4X %n", &opRaw, &charsRead) == 1) {
            unsigned short op = (unsigned short)opRaw;
            const char* name = line + charsRead; // ชี้ไปยังส่วนข้อความหลัง hex+space

            // ถ้าชื่อซ้ำ (opcode เดียวกันปรากฏใน [Recv] และ [Send])
            // เก็บอันแรกที่เจอไว้ก่อน — แก้ได้ด้วยการใส่ prefix ถ้าต้องการ
            if (gOpNameMap.find(op) == gOpNameMap.end()) {
                gOpNameMap[op] = std::string(name);
            }
        }
    }

    fclose(f);
    gOpMapLoaded = true;
    printf("[+] Loaded %zu opcodes from: %s\n", gOpNameMap.size(), txtPath);
}


// ============================================================
//  GetStackTraceDetails — ดึงร่องรอย 4 ชั้น และดึงค่า OpCode
// ============================================================
void GetStackTraceDetails(char* outBuffer, size_t sz) {
    const int MAX_FRAMES = 5; // ดึงมา 5 ชั้น (เผื่อชั้นที่ 1 คือฟังก์ชันนี้เอง)
    void* stack[MAX_FRAMES];
    WORD frames = CaptureStackBackTrace(1, MAX_FRAMES, stack, NULL);

    outBuffer[0] = '\0';
    char temp[256];

    // วนลูปแสดงผลแค่ 4 ชั้นตามต้องการ
    for (WORD i = 0; i < frames && i < 4; i++) {
        unsigned char* codePtr = (unsigned char*)stack[i];
        unsigned char bytes[8] = {0}; // เตรียมอ่านค่า 8 ไบต์

        // ดึงค่าจาก Address โดยตรง (อ่าน Machine Code)
        ReadProcessMemory(GetCurrentProcess(), codePtr, bytes, 8, NULL);

        sprintf_s(temp, sizeof(temp), 
                  "\n         Trace [%d]: 0x%p | OpCode: %02X %02X %02X %02X %02X %02X %02X %02X", 
                  i+1, stack[i], bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);
        
        strcat_s(outBuffer, sz, temp);
    }
}

// ============================================================
//  PrintPacket — แสดง Packet ใน Console (Wireshark-style)
//
//  ตัวอย่าง output:
//  [15:00:03] C->S  OP: 0x0064 (LOGIN_REQ)  Len: 55 bytes
//    0000  64 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |d...............|
//    0010  ...
// ============================================================
void PrintPacket(const char* direction, const char* buf, int len) {
    if (len < 2) return;

    unsigned short opcode = *(unsigned short*)(buf);
    const char*    opname = GetOpName(opcode);
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));

    // C->S = cyan (36), S->C = yellow (33)
    const char* color = (direction[0] == 'C') ? "\033[36m" : "\033[33m";
    printf("%s[%s] %s  OP: 0x%04X (%s)  Len: %d bytes\033[0m\n",
           color, ts, direction, opcode, opname, len);

    // Hex + ASCII dump — 16 bytes ต่อแถว
    for (int row = 0; row < len; row += 16) {
        printf("  %04X  ", row);                           // offset column

        for (int col = 0; col < 16; col++) {               // hex section
            if (row + col < len)
                printf("%02X ", (unsigned char)buf[row + col]);
            else
                printf("   ");                             // padding ให้ ascii ตรง column
            if (col == 7) printf(" ");                     // visual gap กลาง 16 bytes
        }

        printf(" |");                                      // ascii section
        for (int col = 0; col < 16 && (row + col) < len; col++) {
            unsigned char c = (unsigned char)buf[row + col];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.'); // non-printable → '.'
        }
        printf("|\n");
    }
    printf("\n"); // บรรทัดว่างคั่นระหว่าง packet
}

// ============================================================
//  WriteLog — บันทึกลงไฟล์ log 2 รูปแบบในแต่ละ packet:
//  1) Hex string  (grep/ค้นหาง่าย — format เดิม)
//  2) C ByteArray (เอาไป copy วาง packet builder ได้ทันที)
// ============================================================

// เปลี่ยนพารามิเตอร์ตัวสุดท้ายจาก void* caller เป็น const char* stackTrace
void WriteLog(const char* direction, const char* buf, int len, const char* stackTrace) {
    if (len < 2) return;

    FILE* f = NULL;
    if (fopen_s(&f, "D:\\logforai\\Find Packet\\analysis\\analysis.log", "a") != 0) return;

    unsigned short opcode = *(unsigned short*)(buf);
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));

    // บรรทัดแรก ข้อมูล Packet
    fprintf(f, "[%s] [%s] ID: %04X (%s) | Len: %d | Hex: ",
            ts, direction, opcode, GetOpName(opcode), len);
    for (int i = 0; i < len; i++)
        fprintf(f, "%02X ", (unsigned char)buf[i]);

    // แสดง Stack Trace ทั้ง 4 ชั้น พร้อมค่า OpCode
    fprintf(f, "%s", stackTrace);

    // ปิดท้ายด้วย ByteArray
    fprintf(f, "\n         ByteArray: { ");
    for (int i = 0; i < len; i++)
        fprintf(f, "0x%02X%s", (unsigned char)buf[i], (i < len - 1) ? ", " : "");
    fprintf(f, " }\n\n"); 

    fclose(f);
}

// ============================================================
//  Hook Functions — ใช้ Inline Hook (5-byte JMP trampoline)
// ============================================================

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    char stackTrace[1024];
    GetStackTraceDetails(stackTrace, sizeof(stackTrace));

    printf("\033[35m[Call Stack Captured]\033[0m\n");
    PrintPacket("C->S", buf, len);
    WriteLog("C->S", buf, len, stackTrace);

    DWORD old;
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalSend, origSendBytes, 5);
    int res = pOriginalSend(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmp, 5);
    VirtualProtect(pOriginalSend, 5, old, &old);
    return res;
}

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {
    char stackTrace[1024];
    GetStackTraceDetails(stackTrace, sizeof(stackTrace));

    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) {
        printf("\033[35m[Call Stack Captured]\033[0m\n");
        PrintPacket("S->C", buf, res);
        // บันทึกลง Log สำหรับฝั่ง Recv
        WriteLog("S->C", buf, res, stackTrace);
    }
    return res;
}

// ============================================================
//  StartHooking — patch ws2_32!send และ ws2_32!recv
// ============================================================
void StartHooking() {
    char dllPath[MAX_PATH] = {};
    GetModuleFileNameA(gSelfModule, dllPath, MAX_PATH);
    InitConsole(); // เปิด Console ก่อนเสมอ
    LoadOpCodeMap(dllPath);

    
    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) { printf("[!] ws2_32.dll not found.\n"); return; }

    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    if (!pOriginalSend || !pOriginalRecv) {
        printf("[!] Cannot resolve send/recv.\n"); return;
    }

    DWORD old;

    // Hook send()
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origSendBytes, pOriginalSend, 5);
    BYTE jmpS[5] = { 0xE9 };
    *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmpS, 5);
    VirtualProtect(pOriginalSend, 5, old, &old);
    printf("[+] Hooked: ws2_32!send @ 0x%08X\n", (DWORD)pOriginalSend);

    // Hook recv()
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(origRecvBytes, pOriginalRecv, 5);
    BYTE jmpR[5] = { 0xE9 };
    *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmpR, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);
    printf("[+] Hooked: ws2_32!recv @ 0x%08X\n\n", (DWORD)pOriginalRecv);

    printf("Listening for packets...\n");
    printf("----------------------------------------------------------\n\n");
}

// ============================================================
//  DllMain
// ============================================================
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        gSelfModule = h; // เก็บ handle ไว้ให้ StartHooking ใช้หา path ของ DLL
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    }
    return TRUE;
}