#define WIN32_LEAN_AND_MEAN          // บอกให้ windows.h โหลดเฉพาะส่วนที่จำเป็น ลด bloat
#include <windows.h>                 // Windows API หลัก (VirtualProtect, CreateThread ฯลฯ)
#include <winsock2.h>                // Windows Socket API (SOCKET, send, recv)
#include <stdio.h>                   // printf, fprintf, fopen_s, sprintf_s
#include <time.h>                    // time(), localtime_s() — ใช้ทำ timestamp
#include <stdlib.h>                  // malloc(), free() — ใช้ใน ForwardToXkore3()

#pragma comment(lib, "ws2_32.lib")  // บอก Linker ให้ link กับ ws2_32.dll อัตโนมัติ

// ============================================================
//  Type Definitions
// ============================================================

// ประกาศ function pointer type สำหรับ send() ของ Winsock
// ต้องตรงกับ signature จริง: int WSAAPI send(SOCKET, const char*, int, int)
typedef int (WSAAPI* send_t)(SOCKET s, const char* buf, int len, int flags);

// ประกาศ function pointer type สำหรับ recv() ของ Winsock
typedef int (WSAAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

send_t pOriginalSend = NULL;         // เก็บ address ของ send() จริงใน ws2_32.dll
recv_t pOriginalRecv = NULL;         // เก็บ address ของ recv() จริงใน ws2_32.dll
BYTE origSendBytes[5];               // backup 5 bytes แรกของ send() ก่อน patch
BYTE origRecvBytes[5];               // backup 5 bytes แรกของ recv() ก่อน patch
// ============================================================
//  [เพิ่มใหม่] Global State — วางต่อจาก origRecvBytes[5] ที่มีอยู่เดิม
// ============================================================

// ────────── Xkore3 Connection ──────────

static SOCKET g_xkSocket    = INVALID_SOCKET;  // socket แยกต่างหากสำหรับคุยกับ Xkore3
                                                // ไม่ใช่ socket ของ game → เปิดเองใน ConnectXkore3()
static volatile bool g_xkConnected  = false;  // ✅ อ่านจาก memory ทุกครั้ง
                                                // ใช้กันไม่ให้ ConnectXkore3() ถูกเรียกซ้ำ
static volatile bool g_redirectReady = false;  // ✅ อ่านจาก memory ทุกครั้ง
                                                // จะกลายเป็น true ครั้งเดียวตอนเห็น 0x0064 ครั้งแรก
// ────────── Gepard Identity Cache ──────────
#define GEPARD_IDENTITY_LEN 269                 // ขนาดแน่นอนของ Gepard identity packet (bytes)
                                                // ค่านี้มาจาก log: [C->S] ID: 81A8 Len: 269
static BYTE   g_gepardCache[GEPARD_IDENTITY_LEN]; // เก็บ bytes ทั้ง 269 ตัวของ packet ที่ client เคยส่ง
                                                   // ถ้า server ถามซ้ำ DLL จะตอบให้อัตโนมัติโดยใช้ค่านี้
static bool   g_gepardCached = false;           // true = เก็บ cache ไว้แล้ว ไม่ต้อง overwrite ซ้ำ
static int    g_gepardCachedLen = 0;            // ความยาวจริงที่เก็บไว้ (ควรเป็น 269 เสมอ)
// ────────── Gepard Socket Cache ──────────
// เก็บ socket ที่ client ใช้ส่ง packet Len=269 ครั้งแรก
// เพื่อให้ตอน auto-reply ใช้ socket เดิมส่งกลับออกไปถูก port/connection
static SOCKET g_gepardSocket = INVALID_SOCKET;  // socket ที่ใช้ส่ง Gepard identity ครั้งแรก
static FILE* gConOut = NULL;         // FILE* สำหรับ stdout ที่ redirect ไปหน้าต่าง console

// ============================================================
//  [Step 1+2 เพิ่มใหม่] Inject Queue — วางต่อจาก g_gepardSocket ในไฟล์เดิม
//
//  ทำหน้าที่เป็น "กล่องจดหมาย" ระหว่าง 2 thread:
//    - Listener Thread   → เป็นคน "หยอด" packet ลงกล่อง (Push)
//    - MyRecvHook        → เป็นคน "หยิบ" packet ออกจากกล่อง (Pop)
//
//  เราใช้ circular buffer (วงกลม) แทน linked list
//  เพราะ circular buffer ไม่ต้อง malloc/free ตลอด เร็วกว่าและ stable กว่า
//  ในงาน real-time อย่าง game hook ครับ
//
//  ภาพของ circular buffer:
//
//    index: [0][1][2][3][4][5][6][7]...[63]
//                ↑head              ↑tail
//
//    head = ตำแหน่งที่จะ Pop ออก (game จะอ่าน)
//    tail = ตำแหน่งที่จะ Push เข้า (Listener จะเขียน)
//    ถ้า head == tail = queue ว่างเปล่า
//    ถ้า (tail+1) % SIZE == head = queue เต็ม (ทิ้ง packet นั้น)
// ============================================================

// ขนาดสูงสุดของ packet inject แต่ละก้อน
// RO packet ปกติไม่เกิน 8192 bytes จริงๆ แต่เผื่อไว้ครับ
#define INJECT_PKT_MAXLEN  8192

// จำนวน slot ใน circular buffer
// 64 slots หมายความว่า Xkore3 inject ค้างได้สูงสุด 63 packets
// (63 ไม่ใช่ 64 เพราะต้องเว้น 1 slot ไว้แยก full/empty)
#define INJECT_QUEUE_SIZE  64

// โครงสร้างของ packet inject 1 ก้อน
// แต่ละ slot ใน queue เก็บข้อมูลแบบนี้
struct InjectEntry {
    BYTE data[INJECT_PKT_MAXLEN];  // ตัว payload จริงๆ ของ RO packet
                                   // อาจเป็น WALK, ATTACK, หรือ packet อะไรก็ได้
    int  len;                      // ความยาวจริงของ data[] ที่ใช้งานอยู่
                                   // (ส่วนที่เหลือจาก len ถึง INJECT_PKT_MAXLEN เป็น garbage)
};

// ตัว queue จริงๆ — array ของ InjectEntry
static InjectEntry g_injectQueue[INJECT_QUEUE_SIZE]; // circular buffer 64 slots

// head และ tail ของ circular buffer
// volatile บอกให้ compiler ไม่ cache ค่าเหล่านี้ไว้ใน register
// เพราะอีก thread อาจเปลี่ยนค่าได้ตลอดเวลา
static volatile int g_qHead = 0;   // index ที่จะ Pop ออก (game thread อ่าน)
static volatile int g_qTail = 0;   // index ที่จะ Push เข้า (listener thread เขียน)

// CRITICAL_SECTION คือ "กุญแจ" ของ Windows สำหรับป้องกัน race condition
// ก่อนใครก็ตามจะแตะ head/tail หรือข้อมูลใน queue ต้อง EnterCriticalSection ก่อน
// แล้วค่อย LeaveCriticalSection เมื่อเสร็จ
// วิธีนี้ทำให้ทีละ thread เท่านั้นที่จะเข้าไปแตะ queue ได้ในขณะใดขณะหนึ่ง
static CRITICAL_SECTION g_qLock;   // กุญแจ queue — ต้อง InitializeCriticalSection() ก่อนใช้

// ────────── Listener Thread Handle ──────────
static HANDLE g_listenerThread = NULL;  // handle ของ background thread ที่รับจาก Xkore3
                                        // เก็บไว้เพื่อ debug / cleanup เท่านั้น
                                        // ไม่ได้ใช้บังคับ thread ในโค้ดนี้

// ============================================================
//  Forward Declarations — ป้องกัน compile error
//  เพราะ function เหล่านี้ถูกเรียกใช้ก่อนที่จะถูกประกาศตัวจริง
// ============================================================
int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags); // ใช้ใน ForwardToXkore3
int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags);       // ใช้ใน RecvExact
static bool InjectQueue_Push(const BYTE* data, int len);              // ใช้ใน XkoreListenerThread
static int  InjectQueue_Pop(char* outBuf, int bufMaxLen);             // ใช้ใน MyRecvHook


// ============================================================
//  OpCode Table (Ragnarök Online)
// ============================================================

// ฟังก์ชัน helper: รับ opcode (2 bytes แรกของ RO packet) แล้วคืน string ชื่อ packet
const char* GetOpName(unsigned short opcode) {
    switch (opcode) {                            // เปรียบเทียบ opcode กับค่าที่รู้จัก

        // --- Client → Server ---
        case 0x0064: return "LOGIN_REQ";          // Client ส่ง username/password เข้า Login Server
        case 0x0065: return "SELECT_SERVER";      // Client เลือก Game Server ที่จะเข้าเล่น
        case 0x0066: return "SELECT_CHAR";        // Client เลือก character จากหน้า char select
        case 0x007D: return "MAP_LOADED";         // Client แจ้งว่าโหลด map เสร็จแล้ว พร้อมเล่น
        case 0x0078: return "WALK";               // Client ส่งพิกัดปลายทางที่ต้องการเดิน
        case 0x008D: return "ATTACK";             // Client สั่งโจมตี monster/player
        case 0x0093: return "USE_SKILL";          // Client ใช้ skill (version เก่า)
        case 0x009F: return "PICK_UP_ITEM";       // Client เก็บ item บนพื้น
        case 0x00A2: return "DROP_ITEM";          // Client ทิ้ง item จาก inventory
        case 0x00A7: return "ITEM_USE";           // Client ใช้ item (กินยา ฯลฯ)
        case 0x00F3: return "CHAT_SEND";          // Client พิมพ์ข้อความ chat ส่งไป Server
        case 0x0187: return "ACK_MONSTER_HP";     // Client ตอบรับ HP ของ monster
        case 0x035F: return "WALK2";              // Client ส่งพิกัดเดิน (version ใหม่)
        case 0x0360: return "ATTACK2";            // Client สั่งโจมตี (version ใหม่)
        case 0x0436: return "CHAR_SELECT_CONFIRM";// Client ยืนยันการเลือก character
        case 0x0447: return "USE_SKILL2";         // Client ใช้ skill (version ใหม่)
        case 0x4F50: return "HTTP_POST_REQUEST";  // เป็น HTTP (ตัวอักษร 'PO' = POST) ไม่ใช่ RO
        case 0x2D2D: return "HTTP_MULTIPART_DATA";// HTTP multipart boundary '--' ไม่ใช่ RO
        case 0x08C9: return "CZ_COMPLETE_STABLE_STATE"; // Client แจ้ง state เสถียร

        // --- Server → Client ---
        case 0x0080: return "ITEM_PICKUP";        // Server แจ้งว่า item ถูกหยิบขึ้นแล้ว
        case 0x0081: return "DISCONNECT_ACK";     // Server ส่งก่อน kick/disconnect client
        case 0x00B0: return "STATUS_CHANGE";      // Server อัปเดต stat (HP/SP/ATK ฯลฯ)
        case 0x00B6: return "ENTITY_VANISH";      // Server แจ้งว่า entity หายจากหน้าจอ
        case 0x0162: return "SKILL_LIST";         // Server ส่งรายการ skill ทั้งหมดของ char
        case 0x01D7: return "EQUIPMENT_INFO";     // Server ส่งข้อมูล equipment ที่สวมใส่
        case 0x0AC4: return "CHAR_INFO";          // Server ส่งข้อมูล character ทั้งหมด
        case 0x0AC5: return "CHAR_SELECT_RESP";   // Server ตอบกลับหลังเลือก character
        case 0x0B72: return "MAP_ENTITY_LIST";    // Server ส่งรายการ entity รอบๆ ใน map
        case 0x09FF: return "MONSTER_MOVE";       // Server แจ้ง monster กำลังเดิน
        case 0x09A1: return "SPAWN_ENTITY";       // Server สร้าง entity ใหม่ใน map
        case 0x0B1B: return "PING";               // Server ส่ง ping เช็ค latency
        case 0x0087: return "MOVE_ACK";           // Server ยืนยัน character เดินได้
        case 0x0000: return "NULL_PACKET";        // opcode 0 = null / empty
        case 0x01C3: return "ZC_NOTIFY_PLAYERCHAT"; // Server broadcast ข้อความ chat ของ player
        case 0x0B1D: return "PING_REPLY_PONG";    // Server ตอบ pong หลังได้รับ ping
        case 0x007F: return "MAP_ENTER_ACK";      // Server อนุญาตให้ client เข้า map
        case 0x09FD: return "GEPARD_SECURITY_REQUEST";  // Anti-cheat Gepard ขอข้อมูล
        case 0x4753: return "GEPARD_SECURITY_SEED";     // Anti-cheat Gepard ส่ง seed
        case 0xC392: return "GEPARD_SECURITY_RESPONSE"; // Anti-cheat Gepard รับ response
        case 0x5448: return "HTTP_RESPONSE_HEADER"; // HTTP response 'HT' ไม่ใช่ RO packet
        case 0x227B: return "ZC_HOTKEY_CONFIG";   // Server ส่ง config hotkey ของ character
        case 0x0ADE: return "ZC_NOTIFY_PLAYER_CHAT"; // Server แจ้ง player chat
        case 0xB063: return "GEPARD_SECURITY_TABLE_DATA"; // Gepard ส่ง table ข้อมูล
        case 0x8E8A: return "ZC_NOTIFY_MOVE_BATCH";  // Server ส่งการเคลื่อนที่แบบ batch
        case 0x07FB: return "ZC_NOTIFY_MOVE_SINGLE"; // Server ส่งการเคลื่อนที่ entity เดียว
        case 0x0983: return "ZC_NOTIFY_HP";       // Server อัปเดต HP ของ entity
        case 0x09CB: return "ZC_NOTIFY_SP";       // Server อัปเดต SP ของ character
        case 0x8D00: return "ZC_ENTITY_UPDATE_BATCH"; // Server อัปเดต entity หลายตัวพร้อมกัน
        case 0xAEF1: return "GEPARD_RESOURCE_TABLE"; // Gepard ส่ง resource table
        case 0x0196: return "ZC_NOTIFY_PLAYER_MOVE"; // Server แจ้ง player คนอื่นกำลังเดิน
        default:     return "UNKNOWN";            // opcode ที่ยังไม่รู้จัก
    }
}

// ============================================================
//  InitConsole
// ============================================================

void InitConsole() {
    AllocConsole();                              // สร้างหน้าต่าง Console ใหม่แยกจาก process หลัก
    SetConsoleTitleA("[HyBridge] RO Packet Monitor"); // ตั้งชื่อ title bar ของ Console

    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE); // ดึง handle ของ Console output
    COORD bufSize = { 200, 5000 };               // กำหนด buffer: กว้าง 200 cols, สูง 5000 rows
    SetConsoleScreenBufferSize(hCon, bufSize);   // ขยาย scroll buffer ให้เก็บ log ได้เยอะ

    DWORD mode = 0;                              // ตัวแปรเก็บ Console mode เดิม
    GetConsoleMode(hCon, &mode);                 // อ่าน mode ปัจจุบันของ Console
    SetConsoleMode(hCon, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING); // เปิด ANSI color escape (Win10+)

    freopen_s(&gConOut, "CONOUT$", "w", stdout); // redirect stdout → CONOUT$ (Console จริง)

    // แสดง header เมื่อเริ่มต้น
    printf("==========================================================\n");
    printf("  HyBridge :: Ragnarok Online Packet Monitor\n");
    printf("  \033[36m[C->S]\033[0m = Client to Server"
           "   \033[33m[S->C]\033[0m = Server to Client\n"); // \033[36m = cyan, \033[33m = yellow
    printf("==========================================================\n\n");
}

// ============================================================
//  FormatTimestamp
// ============================================================

static void FormatTimestamp(char* out, size_t sz) { // out = buffer รับผล, sz = ขนาด buffer
    time_t now = time(0);                        // ดึง Unix timestamp ปัจจุบัน
    struct tm ltm;                               // struct เก็บเวลาแบบ local (แยก H/M/S)
    localtime_s(&ltm, &now);                     // แปลง Unix time → local time (thread-safe)
    sprintf_s(out, sz, "%02d:%02d:%02d",         // format เป็น HH:MM:SS
              ltm.tm_hour, ltm.tm_min, ltm.tm_sec); // ชั่วโมง, นาที, วินาที
}

// ============================================================
//  PrintPacket — แสดง packet ใน Console แบบ Wireshark
// ============================================================

void PrintPacket(const char* direction, const char* buf, int len) {
    if (len < 2) return;                         // packet ต้องมีอย่างน้อย 2 bytes (opcode)

    unsigned short opcode = *(unsigned short*)(buf); // อ่าน 2 bytes แรกเป็น opcode (little-endian)
    const char*    opname = GetOpName(opcode);   // แปลง opcode → ชื่อ packet
    char ts[16];                                 // buffer เก็บ timestamp string
    FormatTimestamp(ts, sizeof(ts));             // เขียน HH:MM:SS ลง ts

    // เลือกสีตามทิศทาง: C->S = cyan (36), S->C = yellow (33)
    const char* color = (direction[0] == 'C') ? "\033[36m" : "\033[33m";

    // พิมพ์บรรทัดหัว: [เวลา] ทิศทาง  OP: 0xXXXX (ชื่อ)  Len: N bytes
    printf("%s[%s] %s  OP: 0x%04X (%s)  Len: %d bytes\033[0m\n",
           color, ts, direction, opcode, opname, len);

    // Hex + ASCII dump — ทีละ 16 bytes ต่อแถว (เหมือน Wireshark)
    for (int row = 0; row < len; row += 16) {   // วน loop ทีละ 16 bytes
        printf("  %04X  ", row);                 // พิมพ์ offset ของแถว (0000, 0010, 0020 ...)

        for (int col = 0; col < 16; col++) {     // วน 16 columns สำหรับ hex section
            if (row + col < len)                 // ถ้ายังมีข้อมูลในตำแหน่งนี้
                printf("%02X ", (unsigned char)buf[row + col]); // พิมพ์ hex 2 หลัก
            else
                printf("   ");                   // padding 3 ช่อง ให้ ascii column ตรงกัน
            if (col == 7) printf(" ");           // เว้นช่องว่างกลาง เพื่อแบ่ง 8+8
        }

        printf(" |");                            // เริ่ม ascii section
        for (int col = 0; col < 16 && (row + col) < len; col++) { // วนพิมพ์ ascii
            unsigned char c = (unsigned char)buf[row + col]; // ดึง byte
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.'); // printable → แสดง, อื่น → '.'
        }
        printf("|\n");                           // ปิด ascii section แล้วขึ้นบรรทัดใหม่
    }
    printf("\n");                                // บรรทัดว่างคั่นระหว่างแต่ละ packet
}

// ============================================================
//  WriteLog — บันทึกลงไฟล์ log
// ============================================================

void WriteLog(const char* direction, const char* buf, int len) {
    if (len < 2) return;                         // ไม่บันทึกถ้าข้อมูลสั้นเกินไป

    FILE* f = NULL;                              // ตัวแปร FILE pointer
    // เปิดไฟล์ log ต่อท้าย (append mode), ถ้าเปิดไม่ได้ให้ return เลย
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_analysis.log", "a") != 0) return;

    unsigned short opcode = *(unsigned short*)(buf); // อ่าน opcode จาก 2 bytes แรก
    char ts[16];                                 // buffer สำหรับ timestamp
    FormatTimestamp(ts, sizeof(ts));             // เขียน HH:MM:SS ลง ts

    // บรรทัด 1: บันทึก hex dump แบบ inline (grep ง่าย)
    fprintf(f, "[%s] [%s] ID: %04X (%s) | Len: %d | Hex: ",
            ts, direction, opcode, GetOpName(opcode), len); // header ของบรรทัด
    for (int i = 0; i < len; i++)               // วน dump ทุก byte
        fprintf(f, "%02X ", (unsigned char)buf[i]); // พิมพ์เป็น hex

    // บรรทัด 2: บันทึกเป็น C byte array — copy วาง packet builder ได้เลย
    fprintf(f, "\n         ByteArray: { ");      // เยื้องให้ดูง่าย
    for (int i = 0; i < len; i++)               // วน dump ทุก byte
        fprintf(f, "0x%02X%s", (unsigned char)buf[i], (i < len - 1) ? ", " : ""); // 0xXX, ...
    fprintf(f, " }\n");                          // ปิด array แล้วขึ้นบรรทัดใหม่

    fclose(f);                                   // ปิดไฟล์ (flush + release handle)
}


// ============================================================
//  [เพิ่มใหม่] IsGepardPacket — ตรวจว่า packet นี้เป็น Gepard หรือเปล่า
//  วางไว้ก่อน MySendHook เพราะ MySendHook จะเรียกใช้ฟังก์ชันนี้
//  คืนค่า true หากเป็น packet ที่ Client ต้องจัดการเองเสมอ
//  คือไม่ส่งสำเนาให้ Xkore3 และไม่ให้ Xkore3 แทรกแซงเด็ดขาด
//  เหตุผลที่กั้น 3 กลุ่มนี้:
//    1. Len=269       → Gepard identity fingerprint ของเครื่องนี้โดยเฉพาะ
//                       Xkore3 ไม่มีข้อมูลนี้ และไม่ควรเห็นด้วย
//    2. opcode 0x4753 → Seed ที่ server ส่งมาให้ client คำนวณ response
//                       Gepard module ใน game process เป็นคนคำนวณ ต้องให้ client รับเอง
//    3. opcode 0xC392 → Response ที่ client คำนวณได้แล้วส่งคืน server
//                       ต้องส่งตรงไป server โดยไม่ผ่าน Xkore3
// ============================================================

static bool IsGepardPacket(const char* buf, int len) {

    if (len == GEPARD_IDENTITY_LEN) return true;  // Len=269 คือ Gepard identity packet ทุกครั้ง
                                                  // ไม่ต้องดู opcode เพราะ opcode ถูก encrypt แล้ว

    if (len < 2) return false;                    // packet สั้นเกิน อ่าน opcode ไม่ได้ ถือว่าไม่ใช่

    unsigned short op = *(unsigned short*)buf;    // อ่าน opcode จาก 2 bytes แรก (little-endian)

    if (op == 0x4753) return true;                // GEPARD_SECURITY_SEED: server ส่ง seed มาให้ client
    if (op == 0xC392) return true;                // GEPARD_SECURITY_RESPONSE: client ตอบ seed กลับไป

    return false;                                 // ไม่ใช่ Gepard → ส่งได้ตามปกติ
}

// ============================================================
//  [Step 1] XkoreListenerThread — background thread รับคำสั่งจาก Xkore3
//
//  Thread นี้รันตลอดชีวิตของ DLL โดยทำงาน 2 อย่างหลัก:
//    1. รับ framed packet จาก Xkore3 ผ่าน g_xkSocket
//    2. Push payload เข้า Inject Queue เพื่อให้ MyRecvHook ส่งต่อให้ game
//
//  Frame format ที่ Xkore3 จะส่งมา (ตรงกับที่ ForwardToXkore3 ใช้):
//    Byte 0    : direction  0x03 = inject เข้า game client (S->C fake)
//    Byte 1    : reserved   0x00
//    Byte 2-3  : payload_len (little-endian)
//    Byte 4+   : payload ของ RO packet จริงๆ
//
//  ทำไมถึง 0x03?
//    0x01 = DLL ส่ง C->S ไปให้ Xkore3
//    0x02 = DLL ส่ง S->C ไปให้ Xkore3
//    0x03 = Xkore3 สั่ง inject packet เข้า game (ทิศทางที่ 3)
//
//  ปัญหาหลักของ TCP ที่ต้องจัดการ:
//    TCP ไม่รับประกันว่า recv() ครั้งเดียวจะได้ครบ 1 frame
//    อาจได้แค่ครึ่ง header หรือได้ 2 frame มาพร้อมกันก็ได้
//    เราจึงต้องใช้ RecvExact() ที่รับให้ครบก่อน
// ============================================================

// ── Helper: รับข้อมูล TCP ให้ครบตามจำนวน bytes ที่ต้องการ ──────────────────
// TCP recv() อาจคืนน้อยกว่า needLen ได้ เราจึงต้อง loop รับซ้ำจนครบ
// คืนค่า true ถ้ารับครบ, false ถ้า socket ปิดหรือ error
static bool RecvExact(SOCKET sock, BYTE* dst, int needLen) {

    // ดึง address ของ recv() จริงโดยตรงจาก ws2_32.dll ครั้งเดียว
    // ไม่แตะ hook bytes เลย → ปลอดภัย 100% จาก race condition
    typedef int (WSAAPI* raw_recv_t)(SOCKET, char*, int, int);
    static raw_recv_t s_rawRecv = NULL;                // static = เก็บค่าข้ามการเรียกครั้งต่อๆ ไป
    if (!s_rawRecv) {                                  // ดึงแค่ครั้งแรกครั้งเดียว
        s_rawRecv = (raw_recv_t)GetProcAddress(
            GetModuleHandleA("ws2_32.dll"), "recv");   // address จริงของ recv() ใน ws2_32
    }
    if (!s_rawRecv) return false;                      // หาไม่เจอ (แทบเป็นไปไม่ได้)

    int got = 0;                                       // bytes ที่ได้รับมาแล้วสะสม
    while (got < needLen) {                            // วนจนกว่าจะครบ needLen bytes
        int r = s_rawRecv(sock,                        // เรียก recv() ตรงๆ ไม่ผ่าน hook
                          (char*)(dst + got),          // วางต่อจากที่รับมาแล้ว
                          needLen - got,               // ขอแค่ที่ยังขาดอยู่
                          0);                          // flags = 0
        if (r <= 0) return false;                      // socket ปิดหรือ error
        got += r;                                      // สะสม bytes
    }
    return true;                                       // รับครบแล้ว
}


// ── Thread function หลัก ──────────────────────────────────────────────────
// Windows CreateThread ต้องการ function signature แบบนี้
// parameter lpParam เราไม่ใช้ (NULL) แต่ต้องมีตาม spec
static DWORD WINAPI XkoreListenerThread(LPVOID lpParam) {

    char ts[16];
    FormatTimestamp(ts, sizeof(ts));
    printf("\033[35m[%s][Listener] Thread เริ่มทำงาน — รอคำสั่งจาก Xkore3...\033[0m\n", ts);

    BYTE header[4];                                // buffer รับ 4 bytes header ของแต่ละ frame

    // ── วน loop รับ frame จาก Xkore3 ไปเรื่อยๆ ──
    while (true) {

        // ── Step A: รับ header 4 bytes ก่อนเสมอ ──
        if (!RecvExact(g_xkSocket, header, 4)) {   // รับไม่ครบ = socket หลุด
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] socket หลุด — Xkore3 ปิดไปหรือ error\033[0m\n", ts);
            break;                                 // ออกจาก loop หยุด thread
        }

        BYTE   direction  = header[0];             // byte 0: ทิศทาง (0x03 = inject เข้า game)
        // header[1] = reserved ไม่ได้ใช้ตอนนี้
        int    payloadLen = (int)header[2]         // byte 2: low byte ของ len
                          | ((int)header[3] << 8); // byte 3: high byte ของ len (little-endian)

        // ── Validate payload length ──
        if (payloadLen <= 0 || payloadLen > INJECT_PKT_MAXLEN) {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] payloadLen=%d ผิดปกติ"
                " — ตัดการเชื่อมต่อ\033[0m\n", ts, payloadLen);
            break;  // ✅ ออก loop ปิด connection ดีกว่า corrupt ทั้งหมด
        }

        // ── Step B: รับ payload ตามจำนวน bytes ที่ header บอก ──
        BYTE payloadBuf[INJECT_PKT_MAXLEN];        // buffer ชั่วคราวรับ payload
        if (!RecvExact(g_xkSocket, payloadBuf, payloadLen)) { // รับ payload ไม่ครบ
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] รับ payload ไม่ครบ — socket หลุด\033[0m\n", ts);
            break;                                 // ออก loop
        }

        // ── Step C: ตัดสินใจว่าจะทำอะไรกับ frame นี้ตาม direction ──
        if (direction == 0x03) {
            // Xkore3 ต้องการ inject packet เข้า game client
            // เหมือน server ส่ง packet มาให้ game เอง

            unsigned short opcode = *(unsigned short*)payloadBuf; // อ่าน opcode เพื่อ log
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[35m[%s][Inject] รับ inject OP:0x%04X (%s) Len:%d จาก Xkore3\033[0m\n",
                   ts, opcode, GetOpName(opcode), payloadLen);

            bool ok = InjectQueue_Push(payloadBuf, payloadLen); // ใส่คิวรอ game รับ
            if (!ok) {                             // queue เต็ม packet ถูกทิ้ง
                printf("\033[31m[Listener] queue เต็ม! inject packet OP:0x%04X ถูกทิ้ง\033[0m\n",
                       opcode);
            }

        } else {
            // direction อื่นที่ไม่รู้จัก (อนาคตอาจเพิ่ม 0x04, 0x05 สำหรับ command พิเศษ)
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[33m[%s][Listener] direction=0x%02X ไม่รู้จัก ข้ามไป\033[0m\n",
                   ts, direction);
        }
    }

    // ── Thread กำลังจะหยุด ──
    // ตั้ง flag ทั้งหมดเพื่อให้รู้ว่า Xkore3 หลุดออกไปแล้ว
    g_xkConnected  = false;                        // บอกว่า Xkore3 ไม่ได้เชื่อมต่ออยู่แล้ว
    g_redirectReady = false;                       // ปิด redirect: ไม่ forward packet ต่อไปอีก
    if (g_xkSocket != INVALID_SOCKET) {            // ถ้า socket ยังไม่ถูกปิด
        closesocket(g_xkSocket);                   // ปิด socket อย่างสะอาด
        g_xkSocket = INVALID_SOCKET;               // reset ค่า
    }

    FormatTimestamp(ts, sizeof(ts));
    printf("\033[33m[%s][Listener] Thread หยุดทำงานแล้ว"
           " — restart game เพื่อเชื่อมต่อ Xkore3 ใหม่\033[0m\n", ts);

    return 0;                                      // thread จบการทำงาน
}

// ============================================================
//  [เพิ่มใหม่] ConnectXkore3 — เปิด socket แยกต่างหากแล้วต่อไป Xkore3
//
//  ทำไมต้องเป็น socket แยก ไม่ใช่ socket ของ game?
//  เพราะ game มี socket ของตัวเองที่ต่อกับ RO Server อยู่แล้ว
//  ถ้าเราไปแย่งใช้ socket เดิม game จะพัง
//  socket ของเราเป็นช่องทางใหม่ที่ DLL สร้างขึ้นเองเพื่อคุยกับ Xkore3 โดยเฉพาะ
//
//  เรียกฟังก์ชันนี้แค่ครั้งเดียวตอนเจอ 0x0064 ครั้งแรก
// ============================================================

// ============================================================
//  [Step 1 อัพเดต] ConnectXkore3 — แทนที่ version เดิม
//
//  เพิ่มจาก version เดิม 2 อย่าง:
//    1. InitializeCriticalSection(&g_qLock) → เตรียมกุญแจ queue ก่อนใช้งาน
//    2. CreateThread(XkoreListenerThread) → spawn background thread หลังเชื่อมต่อสำเร็จ
//
//  ทำไมต้อง InitializeCriticalSection ที่นี่?
//    เพราะตำแหน่งที่ดีที่สุดคือก่อนที่ thread ใดๆ จะเริ่มใช้งาน queue
//    ถ้า Init ใน StartHooking() ก็ได้ แต่ตรงนี้ชัดเจนกว่าว่า queue ใช้งานได้
//    เมื่อ Xkore3 เชื่อมต่อสำเร็จแล้วเท่านั้น
// ============================================================
static void ConnectXkore3() {

    if (g_xkConnected) return;                      // เชื่อมแล้ว ไม่ต้องทำซ้ำ

    // ── เตรียม CRITICAL_SECTION ก่อนเริ่ม thread ใดๆ ──
    // ถ้าเรียก EnterCriticalSection โดยยัง Init ก่อน = undefined behavior / crash
    InitializeCriticalSection(&g_qLock);            // เตรียม "กุญแจ" queue ให้พร้อมใช้

    // ── สร้าง TCP socket ใหม่สำหรับคุยกับ Xkore3 ──
    g_xkSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                             NULL, 0, 0);            // TCP socket ธรรมดา

    if (g_xkSocket == INVALID_SOCKET) {             // สร้างไม่ได้
        printf("\033[31m[Xkore3] socket() failed err=%d\033[0m\n",
               WSAGetLastError());
        DeleteCriticalSection(&g_qLock);            // คืน CRITICAL_SECTION ด้วยถ้า socket ล้มเหลว
        return;
    }

    // ── กำหนดปลายทาง: Xkore3 ที่ localhost:6901 ──
    sockaddr_in xkAddr  = {};
    xkAddr.sin_family   = AF_INET;                  // IPv4
    xkAddr.sin_port     = htons(6901);              // port data channel ของ Xkore3
    xkAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // localhost เท่านั้น

    // ── เรียก connect() จริงโดยตรง ไม่ผ่าน hook ──
    typedef int (WSAAPI* connect_t)(SOCKET, const sockaddr*, int);
    connect_t rawConnect = (connect_t)GetProcAddress(
        GetModuleHandleA("ws2_32.dll"), "connect"); // ดึง address จริงของ connect()

    if (!rawConnect) {
        printf("\033[31m[Xkore3] cannot find connect()\033[0m\n");
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
        DeleteCriticalSection(&g_qLock);
        return;
    }

    int res = rawConnect(g_xkSocket,                // เรียก connect() จริงไป Xkore3
                         (sockaddr*)&xkAddr,
                         sizeof(xkAddr));

    if (res == SOCKET_ERROR) {                      // connect ล้มเหลว
        printf("\033[31m[Xkore3] connect() failed err=%d"
               " — Xkore3 รันอยู่ไหม?\033[0m\n",
               WSAGetLastError());
        closesocket(g_xkSocket);
        g_xkSocket    = INVALID_SOCKET;
        g_xkConnected = false;
        DeleteCriticalSection(&g_qLock);            // คืน CRITICAL_SECTION
        return;
    }

    // ── เชื่อมต่อสำเร็จ ──
    g_xkConnected  = true;                          // flag: เชื่อมต่อสำเร็จ
    g_redirectReady = true;                         // flag: เปิด forward mode

    char ts[16];
    FormatTimestamp(ts, sizeof(ts));
    printf("\033[32m[%s][Xkore3] เชื่อมต่อ 127.0.0.1:6901 สำเร็จ\033[0m\n", ts);
    printf("\033[32m[Xkore3] Redirect + Inject mode เปิดแล้ว\033[0m\n");

    // ── Spawn Listener Thread เพื่อรับ inject command จาก Xkore3 ──
    // CreateThread คืน handle ของ thread ที่สร้าง เก็บไว้ใน g_listenerThread
    // ถ้าไม่ต้องการ WaitForSingleObject ทีหลัง ก็ CloseHandle(handle) ได้เลย
    // แต่เราเก็บไว้เผื่อ debug ดีกว่า
    g_listenerThread = CreateThread(
        NULL,                                       // security attributes: ใช้ default
        0,                                          // stack size: 0 = ใช้ default ของ Windows
        XkoreListenerThread,                        // function ที่ thread จะรัน
        NULL,                                       // parameter ส่งเข้า thread (เราไม่ใช้)
        0,                                          // creation flags: 0 = เริ่มทันที
        NULL);                                      // thread ID output: NULL = ไม่สนใจ

    if (g_listenerThread == NULL) {                 // สร้าง thread ไม่ได้
        printf("\033[31m[Xkore3] CreateThread ล้มเหลว err=%d"
               " — inject จะไม่ทำงาน\033[0m\n", GetLastError());
        // ไม่ต้อง disconnect เพราะ forward ยังทำงานได้อยู่ แค่ inject ไม่ได้
    } else {
        FormatTimestamp(ts, sizeof(ts));
        printf("\033[32m[%s][Xkore3] Listener Thread เริ่มทำงานแล้ว\033[0m\n\n", ts);
    }
}


// ============================================================
//  [เพิ่มใหม่] ForwardToXkore3 — ห่อ packet ด้วย header แล้วส่งสำเนาไป Xkore3
//
//  Frame format ที่ Xkore3 จะได้รับ:
//
//    Byte 0    : direction  0x01 = C->S,  0x02 = S->C
//    Byte 1    : reserved   0x00 (สำรองไว้สำหรับอนาคต เช่น flags)
//    Byte 2-3  : payload_len  ความยาวของ payload จริง (little-endian 2 bytes)
//    Byte 4+   : payload    ข้อมูล RO packet จริงๆ ทั้งก้อน
//
//  ตัวอย่าง: WALK2 (5 bytes) ขาไป C->S
//    01 00 05 00 5F 03 B5 47 46
//    ^dir ^rsv ^--len--^ ^---payload---^
//
//  Xkore3 อ่าน 4 bytes แรกก่อน → รู้ direction และ len
//  แล้วอ่านต่ออีก len bytes → ได้ payload เต็ม
//
//  Parameters:
//    direction  0x01 = ขาออก (C->S),  0x02 = ขาเข้า (S->C)
//    buf        pointer ไปยัง payload ของ RO packet
//    len        ความยาวของ payload
// ============================================================

static void ForwardToXkore3(BYTE direction, const char* buf, int len) {

    if (!g_xkConnected)               return;
    if (g_xkSocket == INVALID_SOCKET) return;
    if (len <= 0)                      return;

    int frameSize = 4 + len;
    BYTE* frame = (BYTE*)malloc(frameSize);
    if (!frame) return;

    frame[0] = direction;
    frame[1] = 0x00;
    frame[2] = (BYTE)( len       & 0xFF);
    frame[3] = (BYTE)((len >> 8) & 0xFF);
    memcpy(frame + 4, buf, len);

    typedef int (WSAAPI* raw_send_t)(SOCKET, const char*, int, int);
    static raw_send_t s_rawSend = NULL;
    if (!s_rawSend) {
        s_rawSend = (raw_send_t)GetProcAddress(
            GetModuleHandleA("ws2_32.dll"), "send");
    }
    if (!s_rawSend) { free(frame); return; }      // หาไม่เจอ

    int sent = s_rawSend(g_xkSocket, (const char*)frame, frameSize, 0);

    // ❌ ลบ 4 บรรทัดนี้ออกทั้งหมด (ไม่มีใน version ที่ถูกต้อง):
    // DWORD old;
    // BYTE jmp[5] = { 0xE9 };
    // *(DWORD*)(jmp+1) = ...
    // memcpy(pOriginalSend, jmp, 5);
    // VirtualProtect(pOriginalSend, 5, old, &old);

    if (sent == SOCKET_ERROR) {
        printf("\033[31m[Xkore3] ForwardToXkore3 send failed err=%d\033[0m\n",
               WSAGetLastError());
        g_xkConnected  = false;
        g_redirectReady = false;
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
    }

    free(frame);
}

// ============================================================
//  [Step 2] InjectQueue_Push — Listener Thread เรียกเพื่อฝาก packet ลงคิว
//
//  Parameters:
//    data  → pointer ไปยัง payload ของ RO packet ที่ Xkore3 ต้องการ inject
//    len   → ความยาวของ payload
//
//  คืนค่า true ถ้าใส่สำเร็จ, false ถ้า queue เต็ม (packet ถูกทิ้ง)
//
//  เหตุผลที่ต้องล็อก:
//    Listener Thread เรียก Push() ขณะที่ MyRecvHook อาจกำลัง Pop() อยู่บน thread อื่น
//    ถ้าไม่ล็อก tail อาจถูกเขียนทับขณะกำลังอ่านอยู่ → ข้อมูลเสียหาย / crash
// ============================================================
static bool InjectQueue_Push(const BYTE* data, int len) {

    if (len <= 0 || len > INJECT_PKT_MAXLEN) {     // ตรวจขนาด: ไม่รับ packet ที่ 0 หรือใหญ่เกินไป
        printf("\033[31m[Queue] Push ล้มเหลว: len=%d ไม่อยู่ในช่วงที่รับได้\033[0m\n", len);
        return false;                               // ปฏิเสธ packet นี้
    }

    EnterCriticalSection(&g_qLock);                // ล็อก: ขอกุญแจก่อน ถ้ามีคนถือกุญแจอยู่ → รอ

    // ตรวจว่า queue เต็มหรือเปล่า
    // สูตร: ถ้า tail ขยับไป 1 แล้วชนกับ head = เต็ม
    int nextTail = (g_qTail + 1) % INJECT_QUEUE_SIZE; // คำนวณ index ถัดไปของ tail แบบวงกลม
    if (nextTail == g_qHead) {                     // tail ถัดไป == head หมายความว่า queue เต็มแล้ว
        LeaveCriticalSection(&g_qLock);            // คืนกุญแจก่อนออก
        printf("\033[31m[Queue] เต็ม! ทิ้ง inject packet len=%d\033[0m\n", len);
        return false;                              // queue เต็ม ทิ้ง packet นี้ไป
    }

    // ใส่ข้อมูลลง slot ปัจจุบันของ tail
    memcpy(g_injectQueue[g_qTail].data, data, len); // copy payload เข้า slot
    g_injectQueue[g_qTail].len = len;               // บันทึกความยาว

    // ขยับ tail ไปข้างหน้า (แบบวงกลม)
    g_qTail = nextTail;                             // tail เดินหน้า → slot ถัดไปพร้อมรับ packet ใหม่

    LeaveCriticalSection(&g_qLock);                // คืนกุญแจ: thread อื่นเข้าได้แล้ว
    return true;                                   // Push สำเร็จ
}


// ============================================================
//  [Step 2] InjectQueue_Pop — MyRecvHook เรียกเพื่อดึง packet ออกจากคิว
//
//  Parameters:
//    outBuf    → buffer ของ game ที่จะรับข้อมูล (คือ buf ของ MyRecvHook)
//    bufMaxLen → ขนาดสูงสุดที่ buffer รับได้ (คือ len ของ MyRecvHook)
//
//  คืนค่า:
//    > 0   → จำนวน bytes ที่ copy ลง outBuf (= ขนาด packet inject)
//    0     → queue ว่าง ไม่มีอะไรให้ pop
//   -1     → packet ใน queue ใหญ่เกินกว่า bufMaxLen รับได้ (ข้ามไป)
//
//  เหตุผลที่ต้องล็อกตรงนี้ด้วย:
//    MyRecvHook รันบน game thread ขณะที่ Listener Thread อาจกำลัง Push() อยู่
//    ต้องล็อกให้ตรงกันเพื่อป้องกัน head/tail ค่า inconsistent
// ============================================================
static int InjectQueue_Pop(char* outBuf, int bufMaxLen) {

    EnterCriticalSection(&g_qLock);                // ล็อก: ขอกุญแจ

    // ตรวจว่า queue ว่างหรือเปล่า
    // สูตร: ถ้า head == tail = ว่าง (ไม่มีอะไรรอ)
    if (g_qHead == g_qTail) {                      // head ชนกับ tail = queue ว่าง
        LeaveCriticalSection(&g_qLock);            // คืนกุญแจ
        return 0;                                  // ไม่มีอะไร
    }

    // ดึงข้อมูลจาก slot ปัจจุบันของ head
    int pktLen = g_injectQueue[g_qHead].len;       // ความยาวของ packet ที่รอ inject

    if (pktLen > bufMaxLen) {                      // packet ใหญ่เกินกว่า game buffer รับได้
        // ข้ามไปเลย ไม่ copy (เพราะถ้า copy ก็ overflow buffer ของ game)
        g_qHead = (g_qHead + 1) % INJECT_QUEUE_SIZE; // ขยับ head ทิ้ง slot นี้ไป
        LeaveCriticalSection(&g_qLock);            // คืนกุญแจ
        printf("\033[31m[Queue] Pop ข้าม: packet len=%d > bufMaxLen=%d\033[0m\n",
               pktLen, bufMaxLen);
        return -1;                                 // แจ้งว่าข้ามไป
    }

    // copy ข้อมูลออกมาให้ game
    memcpy(outBuf, g_injectQueue[g_qHead].data, pktLen); // copy payload ลง buffer ของ game

    // ขยับ head ไปข้างหน้า (แบบวงกลม)
    g_qHead = (g_qHead + 1) % INJECT_QUEUE_SIZE;  // head เดินหน้า → slot นี้ว่างแล้ว

    LeaveCriticalSection(&g_qLock);                // คืนกุญแจ
    return pktLen;                                 // คืนจำนวน bytes ที่ copy ลง outBuf
}




// ============================================================
//  Hook Functions — Inline Hook แบบ 5-byte JMP trampoline
// ============================================================
//  Decision tree:
//
//  packet เข้ามา
//      │
//      ├─ Len == 269? ──────────────────→ cache ไว้ + ส่งปกติ (ไม่ forward Xkore3)
//      │
//      ├─ opcode == 0xC392? ────────────→ ส่งปกติ (ไม่ forward Xkore3)
//      │   (GEPARD_SECURITY_RESPONSE)
//      │
//      ├─ opcode == 0x0064 และ len==55? → เปิด redirect + ConnectXkore3() + ส่งปกติ
//      │   (LOGIN_REQ จริง)
//      │
//      └─ redirect เปิดอยู่? ──────────→ ส่งปกติ + ForwardToXkore3(C->S, ...)
//          ถ้าไม่ → ส่งปกติเฉยๆ
//
//  "ส่งปกติ" = trampoline: unhook → call send() จริง → re-hook
// ============================================================

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {

    // ──── Guard: packet สั้นเกินไปจนอ่าน opcode ไม่ได้ ────
    if (s == g_xkSocket) goto send_normal;   // ← เพิ่มบรรทัดนี้บรรทัดเดียว

    // ──── Guard: packet สั้นเกินไปจนอ่าน opcode ไม่ได้ ────
    if (len < 2) {
        goto send_normal;
    }

    {   // เปิด scope เพื่อให้ประกาศตัวแปรหลัง goto ได้
        unsigned short opcode = *(unsigned short*)buf; // อ่าน opcode จาก 2 bytes แรก (little-endian)

        // ──── [1] Cache Gepard identity packet (Len=269) ────
        // ทำก่อนทุกอย่างเพราะต้องเก็บไว้ก่อนที่จะตัดสินใจ forward หรือไม่
        if (len == GEPARD_IDENTITY_LEN && !g_gepardCached) {
            memcpy(g_gepardCache, buf, len);        // copy ทุก byte เข้า cache buffer
            g_gepardCachedLen = len;                // บันทึกความยาวจริง (= 269)
            g_gepardCached    = true;               // ตั้ง flag ว่าเก็บไว้แล้ว ไม่ต้อง overwrite ซ้ำ
            g_gepardSocket    = s;                  // จำ socket ที่ใช้ส่ง เพื่อ auto-reply ทีหลัง
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[32m[%s][Gepard] Cache identity packet %d bytes สำเร็จ"
                   " — จะ auto-reply ถ้า server ถามซ้ำ\033[0m\n", ts, len);
        }

        // ──── [2] ตรวจ Gepard packet → ส่งตรงไป server เสมอ ห้าม forward Xkore3 ────
        if (IsGepardPacket(buf, len)) {             // Len=269 หรือ opcode 0xC392 หรือ 0x4753
            PrintPacket("C->S[GEP]", buf, len);    // log พร้อม tag [GEP] ให้รู้ว่าเป็น Gepard
            WriteLog("C->S", buf, len);
            goto send_normal;                       // ส่งตรงไป RO server ห้ามผ่าน Xkore3
        }

        // ──── [3] ตรวจ LOGIN_REQ (0x0064, Len=55) → เปิด redirect ────
        // เปิดเฉพาะตอนที่ login packet มีข้อมูลจริง (Len=55 = version ที่มี username/password)
        // ถ้า Len=55 ทุก byte เป็น 0x00 คือ login blank ที่ส่งก่อน Gepard handshake → ข้ามไป
        if (opcode == 0x0064 && len == 55) {
            // ตรวจว่า payload ไม่ใช่ all-zero (login blank)
            bool allZero = true;                    // สมมติว่าเป็น all-zero ก่อน
            for (int i = 4; i < len && allZero; i++) { // เริ่มจาก byte 4 (ข้าม opcode+version)
                if ((unsigned char)buf[i] != 0x00) allZero = false; // เจอ byte ที่ไม่ใช่ 0
            }

            if (!allZero && !g_redirectReady) {     // เป็น LOGIN_REQ จริงที่มีข้อมูล และยังไม่เปิด redirect
                char ts[16]; FormatTimestamp(ts, sizeof(ts));
                printf("\033[35m[%s][Redirect] ตรวจพบ LOGIN_REQ จริง"
                       " → เปิด redirect mode\033[0m\n", ts);
                ConnectXkore3();                    // เชื่อมต่อ Xkore3 ตอนนี้เลย (ครั้งเดียว)
            }
        }

        // ──── [4] Log ทุก packet ที่ไม่ใช่ Gepard ────
        PrintPacket("C->S", buf, len);
        WriteLog("C->S", buf, len);

        // ──── [5] Forward สำเนาไป Xkore3 ถ้า redirect เปิดอยู่ ────
        if (g_redirectReady) {                      // redirect เปิดอยู่ = เชื่อม Xkore3 สำเร็จแล้ว
            ForwardToXkore3(0x01, buf, len);        // 0x01 = C->S
        }
    }

// ──── Trampoline: ส่งข้อมูลจริงออกไปยัง RO Server ────
send_normal:
    {
        DWORD old;
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old); // ปลดล็อก write protect
        memcpy(pOriginalSend, origSendBytes, 5);    // คืน 5 bytes เดิม (ถอด JMP ออก)
        int res = pOriginalSend(s, buf, len, flags); // เรียก send() จริงของ Winsock → ส่งไป RO Server

        BYTE jmp[5] = { 0xE9 };                     // สร้าง JMP instruction ใหม่
        *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5; // relative offset
        memcpy(pOriginalSend, jmp, 5);              // ใส่ JMP กลับเข้า send()
        VirtualProtect(pOriginalSend, 5, old, &old); // คืน memory protection
        return res;                                 // คืนผลของ send() จริงให้ game
    }
}

// ============================================================
//  [Step 1+2 อัพเดต] MyRecvHook — เวอร์ชันสมบูรณ์พร้อม Inject Queue
//
//  เพิ่มจาก version เดิม 1 อย่าง:
//    ก่อนที่จะ recv() จาก RO Server จริงๆ ให้เช็ค Inject Queue ก่อนเสมอ
//    ถ้ามี packet inject รออยู่ → ส่งให้ game เลย โดยไม่ต้องไปรอ RO Server
//    ถ้าไม่มี → ทำงานปกติ recv() จาก RO Server ต่อไป
//
//  ทำไมถึงเช็ค Queue ก่อน recv() จริง ไม่ใช่หลัง?
//
//    ลองนึกภาพว่า game กำลัง "รอ" ข้อมูลจาก server โดยเรียก recv()
//    recv() จะ block อยู่จนกว่า RO Server จะส่งอะไรมา
//    ถ้าเราเช็ค queue หลัง recv() แล้ว packet inject ใน queue
//    จะต้องรอจนกว่า RO Server จะส่งอะไรมาก่อนถึงจะได้ส่งให้ game
//    ซึ่งอาจช้ามาก เช่น ถ้า server ไม่ส่งอะไรนานๆ inject ก็จะค้างอยู่นาน
//
//    ดังนั้นเช็ค queue ก่อน = inject ทันที ไม่ต้องรอ server ครับ
//
//  Decision tree เวอร์ชันสมบูรณ์:
//
//    game เรียก recv(buf, maxLen)
//        │
//        ├─ Inject Queue มี packet รออยู่?
//        │       ↓ Yes
//        │   Pop ออกมา → copy ลง buf
//        │   return ทันที (ไม่ recv จาก RO Server)
//        │
//        └─ Queue ว่าง → recv จาก RO Server ตามปกติ
//                │
//                ├─ res <= 0 → คืนค่าเลย
//                ├─ opcode 0x4753 → log [GEP] ไม่ forward
//                └─ ปกติ → log + forward Xkore3
// ============================================================

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {

    // ────────────────────────────────────────────────────────
    //  [ใหม่] เช็ค Inject Queue ก่อนเป็นอันดับแรก
    //  ถ้ามี inject packet รออยู่ ส่งให้ game เลยโดยไม่ recv จาก server
    // ────────────────────────────────────────────────────────
    if (g_redirectReady) {                         // inject ทำงานได้เฉพาะหลัง redirect เปิด

        int injected = InjectQueue_Pop(buf, len);  // ลองดึง packet inject จากคิว

        if (injected > 0) {                        // มี inject packet → ส่งให้ game เลย
            unsigned short opcode = *(unsigned short*)buf; // อ่าน opcode เพื่อ log
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[35m[%s][Inject] ส่ง OP:0x%04X (%s) Len:%d เข้า game สำเร็จ\033[0m\n",
                   ts, opcode, GetOpName(opcode), injected);
            WriteLog("S->C[INJ]", buf, injected);  // log พร้อม tag [INJ] ให้รู้ว่าเป็น inject
            return injected;                       // คืนให้ game เลย ไม่ recv จาก server
        }
        // injected == 0 → queue ว่าง ดำเนินการ recv จาก RO Server ต่อไปปกติ
        // injected == -1 → packet ใหญ่เกิน buf รับได้ ก็ดำเนินการต่อปกติ
    }

    // ────────────────────────────────────────────────────────
    //  Trampoline: recv จาก RO Server จริง (เหมือนเดิม)
    // ────────────────────────────────────────────────────────
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old); // ปลดล็อก write protect
    memcpy(pOriginalRecv, origRecvBytes, 5);        // คืน 5 bytes เดิม (ถอด JMP)
    int res = pOriginalRecv(s, buf, len, flags);    // recv() จริง → ข้อมูลจาก RO Server เข้า buf

    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5; // relative offset
    memcpy(pOriginalRecv, jmp, 5);                  // ใส่ JMP กลับ
    VirtualProtect(pOriginalRecv, 5, old, &old);    // คืน memory protection

    if (res <= 0) return res;                       // ไม่มีข้อมูล / error คืนค่าเลย

    if (res >= 2) {                                 // มีข้อมูลพอที่จะอ่าน opcode ได้
        unsigned short opcode = *(unsigned short*)buf;

        // GEPARD_SECURITY_SEED → client จัดการเองเสมอ ไม่ forward Xkore3
        if (opcode == 0x4753) {
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[32m[%s][Gepard] รับ SECURITY_SEED (0x4753) Len:%d"
                   " → client จะคำนวณ response เอง\033[0m\n", ts, res);
            WriteLog("S->C", buf, res);
            return res;                             // คืนให้ game ทันที ไม่ forward
        }

        // packet ปกติ
        PrintPacket("S->C", buf, res);
        WriteLog("S->C", buf, res);

        // forward สำเนาไป Xkore3 ถ้า redirect เปิดอยู่
        if (g_redirectReady) {
            ForwardToXkore3(0x02, buf, res);        // 0x02 = S->C
        }
    }

    return res;                                     // คืนค่า bytes ที่ได้รับจริง
}

// ============================================================
//  StartHooking — patch ws2_32!send และ ws2_32!recv
// ============================================================

void StartHooking() {
    InitConsole();                               // เปิด Console ก่อนเสมอ เพื่อให้ printf ทำงาน

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll"); // หา handle ของ ws2_32.dll ที่โหลดอยู่ใน process
    if (!hWs2) { printf("[!] ws2_32.dll not found.\n"); return; } // ถ้าหาไม่เจอ หยุด

    pOriginalSend = (send_t)GetProcAddress(hWs2, "send"); // หา address ของ send() ใน ws2_32
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv"); // หา address ของ recv() ใน ws2_32
    if (!pOriginalSend || !pOriginalRecv) {      // ถ้าหา function ไม่เจอ
        printf("[!] Cannot resolve send/recv.\n"); return; // แสดง error แล้วหยุด
    }

    DWORD old;                                   // ตัวแปรเก็บ memory protection เดิม

    // --- Hook send() ---
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old); // ปลดล็อก 5 bytes
    memcpy(origSendBytes, pOriginalSend, 5);     // backup 5 bytes เดิมของ send()
    BYTE jmpS[5] = { 0xE9 };                     // สร้าง JMP instruction (E9 = near jump)
    *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5; // relative offset ไป MySendHook
    memcpy(pOriginalSend, jmpS, 5);              // เขียนทับ 5 bytes แรกของ send() ด้วย JMP
    VirtualProtect(pOriginalSend, 5, old, &old); // คืน memory protection เดิม
    printf("[+] Hooked: ws2_32!send @ 0x%08X\n", (DWORD)pOriginalSend); // แจ้งสำเร็จ

    // --- Hook recv() ---
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old); // ปลดล็อก 5 bytes
    memcpy(origRecvBytes, pOriginalRecv, 5);     // backup 5 bytes เดิมของ recv()
    BYTE jmpR[5] = { 0xE9 };                     // สร้าง JMP instruction
    *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5; // relative offset ไป MyRecvHook
    memcpy(pOriginalRecv, jmpR, 5);              // เขียนทับ 5 bytes แรกของ recv() ด้วย JMP
    VirtualProtect(pOriginalRecv, 5, old, &old); // คืน memory protection เดิม
    printf("[+] Hooked: ws2_32!recv @ 0x%08X\n\n", (DWORD)pOriginalRecv); // แจ้งสำเร็จ

    printf("Listening for packets...\n");        // แจ้งว่าพร้อม intercept packet แล้ว
    printf("----------------------------------------------------------\n\n"); // เส้นคั่น
}

// ============================================================
//  DllMain — Entry point ของ DLL
// ============================================================

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lp) { // h = handle ของ DLL นี้
    if (reason == DLL_PROCESS_ATTACH) {          // ถ้า DLL ถูก inject เข้า process
        DisableThreadLibraryCalls(h);            // ปิด DLL_THREAD_ATTACH/DETACH notifications (optimize)
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartHooking, 0, 0, 0); // รัน StartHooking บน thread ใหม่
    }
    return TRUE;                                 // คืน TRUE = DLL load สำเร็จ
}