#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>

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

// ============================================================
//  OpCode Table (Ragnarök Online)
// ============================================================
const char* GetOpName(unsigned short opcode) {
    switch (opcode) {
        // --- Client → Server ---
        case 0x0064: return "LOGIN_REQ";
        case 0x0065: return "SELECT_SERVER";
        case 0x0066: return "SELECT_CHAR";
        case 0x007D: return "MAP_LOADED";
        case 0x0078: return "WALK";
        case 0x008D: return "ATTACK";
        case 0x0093: return "USE_SKILL";
        case 0x009F: return "PICK_UP_ITEM";
        case 0x00A2: return "DROP_ITEM";
        case 0x00A7: return "ITEM_USE";
        case 0x00F3: return "CHAT_SEND";
        case 0x0187: return "ACK_MONSTER_HP";
        case 0x035F: return "WALK2";
        case 0x0360: return "ATTACK2";
        case 0x0436: return "CHAR_SELECT_CONFIRM";
        case 0x0447: return "USE_SKILL2";
        // --- Server → Client ---
        case 0x0080: return "ITEM_PICKUP";
        case 0x0081: return "DISCONNECT_ACK";
        case 0x00B0: return "STATUS_CHANGE";
        case 0x00B6: return "ENTITY_VANISH";
        case 0x0162: return "SKILL_LIST";
        case 0x01D7: return "EQUIPMENT_INFO";
        case 0x0AC4: return "CHAR_INFO";
        case 0x0AC5: return "CHAR_SELECT_RESP";
        case 0x0B72: return "MAP_ENTITY_LIST";
        case 0x09FF: return "MONSTER_MOVE";
        case 0x09A1: return "SPAWN_ENTITY";
        case 0x0B1B: return "PING";
        case 0x0087: return "MOVE_ACK";
        case 0x0000: return "NULL_PACKET";
        default:     return "UNKNOWN";
    }
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
void WriteLog(const char* direction, const char* buf, int len) {
    if (len < 2) return;

    FILE* f = NULL;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_analysis.log", "a") != 0) return;

    unsigned short opcode = *(unsigned short*)(buf);
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));

    // บรรทัด 1: Hex — format เดิม
    fprintf(f, "[%s] [%s] ID: %04X (%s) | Len: %d | Hex: ",
            ts, direction, opcode, GetOpName(opcode), len);
    for (int i = 0; i < len; i++)
        fprintf(f, "%02X ", (unsigned char)buf[i]);

    // บรรทัด 2: Byte Array แบบ C-style
    fprintf(f, "\n         ByteArray: { ");
    for (int i = 0; i < len; i++)
        fprintf(f, "0x%02X%s", (unsigned char)buf[i], (i < len - 1) ? ", " : "");
    fprintf(f, " }\n");

    fclose(f);
}

// ============================================================
//  Hook Functions — ใช้ Inline Hook (5-byte JMP trampoline)
// ============================================================

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {
    // Log ก่อนส่งของจริง เพื่อให้เห็น intent ของ client
    PrintPacket("C->S", buf, len);
    WriteLog("C->S", buf, len);

    // Trampoline: คืน original bytes ชั่วคราว → call จริง → re-hook
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
    // Trampoline ก่อน: รับข้อมูลจริงเข้า buf แล้วค่อย log
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);
    int res = pOriginalRecv(s, buf, len, flags);
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res > 0) {
        PrintPacket("S->C", buf, res);
        WriteLog("S->C", buf, res);
    }
    return res;
}

// ============================================================
//  StartHooking — patch ws2_32!send และ ws2_32!recv
// ============================================================
void StartHooking() {
    InitConsole(); // เปิด Console ก่อนเสมอ

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
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0);
    }
    return TRUE;
}