#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

// ============================================================
//  Type Definitions
// ============================================================

typedef int (WSAAPI* send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI* recv_t)(SOCKET, char*, int, int);

send_t pOriginalSend = nullptr;
recv_t pOriginalRecv = nullptr;
BYTE   origSendBytes[5];
BYTE   origRecvBytes[5];

// ============================================================
//  Global State
// ============================================================

// -- Xkore3 connection --
static SOCKET          g_xkSocket     = INVALID_SOCKET;
static volatile bool   g_xkConnected  = false;
static volatile bool   g_redirectReady = false;

// -- Gepard anti-cheat cache --
#define GEPARD_IDENTITY_LEN 269          // fixed size observed from log: ID 81A8, Len 269
static BYTE   g_gepardCache[GEPARD_IDENTITY_LEN];
static bool   g_gepardCached    = false;
static int    g_gepardCachedLen = 0;
static SOCKET g_gepardSocket    = INVALID_SOCKET;  // socket used for auto-reply (reserved)

static FILE* gConOut = nullptr;

// -- Inject queue (circular buffer, Xkore3 → game) --
#define INJECT_PKT_MAXLEN  8192
#define INJECT_QUEUE_SIZE  64

struct InjectEntry {
    BYTE data[INJECT_PKT_MAXLEN];
    int  len;
};

static InjectEntry       g_injectQueue[INJECT_QUEUE_SIZE];
static volatile int      g_qHead = 0;              // consumer index (MyRecvHook)
static volatile int      g_qTail = 0;              // producer index (XkoreListenerThread)
static CRITICAL_SECTION  g_qLock;

static HANDLE g_listenerThread = nullptr;

// ============================================================
//  Forward Declarations
// ============================================================

int WSAAPI MySendHook(SOCKET, const char*, int, int);
int WSAAPI MyRecvHook(SOCKET, char*, int, int);
static bool InjectQueue_Push(const BYTE* data, int len);
static int  InjectQueue_Pop(char* outBuf, int bufMaxLen);

// ============================================================
//  OpCode Table
// ============================================================

const char* GetOpName(unsigned short op) {
    switch (op) {
        // Client → Server
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
        case 0x4F50: return "HTTP_POST_REQUEST";
        case 0x2D2D: return "HTTP_MULTIPART_DATA";
        case 0x08C9: return "CZ_COMPLETE_STABLE_STATE";
        // Server → Client
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
        case 0x01C3: return "ZC_NOTIFY_PLAYERCHAT";
        case 0x0B1D: return "PING_REPLY_PONG";
        case 0x007F: return "MAP_ENTER_ACK";
        case 0x09FD: return "GEPARD_SECURITY_REQUEST";
        case 0x4753: return "GEPARD_SECURITY_SEED";
        case 0xC392: return "GEPARD_SECURITY_RESPONSE";
        case 0x5448: return "HTTP_RESPONSE_HEADER";
        case 0x227B: return "ZC_HOTKEY_CONFIG";
        case 0x0ADE: return "ZC_NOTIFY_PLAYER_CHAT";
        case 0xB063: return "GEPARD_SECURITY_TABLE_DATA";
        case 0x8E8A: return "ZC_NOTIFY_MOVE_BATCH";
        case 0x07FB: return "ZC_NOTIFY_MOVE_SINGLE";
        case 0x0983: return "ZC_NOTIFY_HP";
        case 0x09CB: return "ZC_NOTIFY_SP";
        case 0x8D00: return "ZC_ENTITY_UPDATE_BATCH";
        case 0xAEF1: return "GEPARD_RESOURCE_TABLE";
        case 0x0196: return "ZC_NOTIFY_PLAYER_MOVE";
        default:     return "UNKNOWN";
    }
}

// ============================================================
//  Console & Logging Helpers
// ============================================================

void InitConsole() {
    AllocConsole();
    SetConsoleTitleA("[HyBridge] RO Packet Monitor");

    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD  sz   = { 200, 5000 };
    SetConsoleScreenBufferSize(hCon, sz);

    DWORD mode = 0;
    GetConsoleMode(hCon, &mode);
    SetConsoleMode(hCon, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    freopen_s(&gConOut, "CONOUT$", "w", stdout);

    printf("==========================================================\n");
    printf("  HyBridge :: Ragnarok Online Packet Monitor\n");
    printf("  \033[36m[C->S]\033[0m Client to Server"
           "   \033[33m[S->C]\033[0m Server to Client\n");
    printf("==========================================================\n\n");
}

static void FormatTimestamp(char* out, size_t sz) {
    time_t now = time(nullptr);
    struct tm ltm;
    localtime_s(&ltm, &now);
    sprintf_s(out, sz, "%02d:%02d:%02d", ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
}

// Wireshark-style hex+ASCII dump
void PrintPacket(const char* dir, const char* buf, int len) {
    if (len < 2) return;

    unsigned short op = *(unsigned short*)buf;
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));

    const char* color = (dir[0] == 'C') ? "\033[36m" : "\033[33m";
    printf("%s[%s] %s  OP: 0x%04X (%s)  Len: %d\033[0m\n",
           color, ts, dir, op, GetOpName(op), len);

    for (int row = 0; row < len; row += 16) {
        printf("  %04X  ", row);
        for (int col = 0; col < 16; col++) {
            if (row + col < len) printf("%02X ", (unsigned char)buf[row + col]);
            else                 printf("   ");
            if (col == 7)        printf(" ");
        }
        printf(" |");
        for (int col = 0; col < 16 && (row + col) < len; col++) {
            unsigned char c = (unsigned char)buf[row + col];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
    printf("\n");
}

void WriteLog(const char* dir, const char* buf, int len) {
    if (len < 2) return;

    FILE* f = nullptr;
    if (fopen_s(&f, "C:\\Users\\Public\\bamboo_analysis.log", "a") != 0) return;

    unsigned short op = *(unsigned short*)buf;
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));

    fprintf(f, "[%s] [%s] ID: %04X (%s) | Len: %d | Hex: ",
            ts, dir, op, GetOpName(op), len);
    for (int i = 0; i < len; i++)
        fprintf(f, "%02X ", (unsigned char)buf[i]);

    fprintf(f, "\n         ByteArray: { ");
    for (int i = 0; i < len; i++)
        fprintf(f, "0x%02X%s", (unsigned char)buf[i], (i < len - 1) ? ", " : "");
    fprintf(f, " }\n");

    fclose(f);
}

// ============================================================
//  Gepard Anti-cheat Filter
//  Returns true for packets that must bypass Xkore3 entirely.
// ============================================================

static bool IsGepardPacket(const char* buf, int len) {
    if (len == GEPARD_IDENTITY_LEN) return true;   // identity fingerprint (encrypted, fixed 269 b)
    if (len < 2) return false;
    unsigned short op = *(unsigned short*)buf;
    return (op == 0x4753 || op == 0xC392);         // SEED or RESPONSE
}

// ============================================================
//  RecvExact — reads exactly needLen bytes from a raw socket
//  (bypasses the hook; used by the listener thread)
// ============================================================

static bool RecvExact(SOCKET sock, BYTE* dst, int needLen) {
    typedef int (WSAAPI* raw_recv_t)(SOCKET, char*, int, int);
    static raw_recv_t s_rawRecv = nullptr;
    if (!s_rawRecv)
        s_rawRecv = (raw_recv_t)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "recv");
    if (!s_rawRecv) return false;

    int got = 0;
    while (got < needLen) {
        int r = s_rawRecv(sock, (char*)(dst + got), needLen - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

// ============================================================
//  XkoreListenerThread
//  Receives framed packets from Xkore3 and pushes them into
//  the inject queue.
//
//  Wire frame layout (4-byte header + payload):
//    [0]   direction  : 0x03 = inject into game (S->C fake)
//    [1]   reserved   : 0x00
//    [2-3] payload_len: little-endian
//    [4+]  payload    : raw RO packet bytes
// ============================================================

static DWORD WINAPI XkoreListenerThread(LPVOID) {
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));
    printf("\033[35m[%s][Listener] started — waiting for Xkore3 commands\033[0m\n", ts);

    BYTE header[4];
    while (true) {
        // Step A: read 4-byte frame header
        if (!RecvExact(g_xkSocket, header, 4)) {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] socket closed or error\033[0m\n", ts);
            break;
        }

        BYTE direction  = header[0];
        int  payloadLen = (int)header[2] | ((int)header[3] << 8);

        if (payloadLen <= 0 || payloadLen > INJECT_PKT_MAXLEN) {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] invalid payloadLen=%d — disconnecting\033[0m\n",
                   ts, payloadLen);
            break;
        }

        // Step B: read payload
        BYTE payload[INJECT_PKT_MAXLEN];
        if (!RecvExact(g_xkSocket, payload, payloadLen)) {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] incomplete payload — disconnecting\033[0m\n", ts);
            break;
        }

        // Step C: dispatch
        if (direction == 0x03) {
            unsigned short op = *(unsigned short*)payload;
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[35m[%s][Inject] OP:0x%04X (%s) Len:%d from Xkore3\033[0m\n",
                   ts, op, GetOpName(op), payloadLen);

            if (!InjectQueue_Push(payload, payloadLen))
                printf("\033[31m[Listener] queue full! OP:0x%04X dropped\033[0m\n", op);
        } else {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[33m[%s][Listener] unknown direction=0x%02X — skipping\033[0m\n",
                   ts, direction);
        }
    }

    // Cleanup on disconnect
    g_xkConnected  = false;
    g_redirectReady = false;
    if (g_xkSocket != INVALID_SOCKET) {
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
    }

    FormatTimestamp(ts, sizeof(ts));
    printf("\033[33m[%s][Listener] thread stopped — restart game to reconnect\033[0m\n", ts);
    return 0;
}

// ============================================================
//  ConnectXkore3
//  Opens a dedicated TCP connection to Xkore3 at 127.0.0.1:6901
//  and spawns XkoreListenerThread.  Called once on first LOGIN_REQ.
// ============================================================

static void ConnectXkore3() {
    if (g_xkConnected) return;

    InitializeCriticalSection(&g_qLock);

    g_xkSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (g_xkSocket == INVALID_SOCKET) {
        printf("\033[31m[Xkore3] socket() failed err=%d\033[0m\n", WSAGetLastError());
        DeleteCriticalSection(&g_qLock);
        return;
    }

    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(6901);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    typedef int (WSAAPI* connect_t)(SOCKET, const sockaddr*, int);
    connect_t rawConnect = (connect_t)GetProcAddress(
        GetModuleHandleA("ws2_32.dll"), "connect");

    if (!rawConnect) {
        printf("\033[31m[Xkore3] cannot resolve connect()\033[0m\n");
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
        DeleteCriticalSection(&g_qLock);
        return;
    }

    if (rawConnect(g_xkSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("\033[31m[Xkore3] connect() failed err=%d — is Xkore3 running?\033[0m\n",
               WSAGetLastError());
        closesocket(g_xkSocket);
        g_xkSocket    = INVALID_SOCKET;
        g_xkConnected = false;
        DeleteCriticalSection(&g_qLock);
        return;
    }

    g_xkConnected  = true;
    g_redirectReady = true;

    char ts[16];
    FormatTimestamp(ts, sizeof(ts));
    printf("\033[32m[%s][Xkore3] connected to 127.0.0.1:6901 — redirect+inject active\033[0m\n\n", ts);

    g_listenerThread = CreateThread(nullptr, 0, XkoreListenerThread, nullptr, 0, nullptr);
    if (!g_listenerThread)
        printf("\033[31m[Xkore3] CreateThread failed err=%d — inject disabled\033[0m\n",
               GetLastError());
    else {
        FormatTimestamp(ts, sizeof(ts));
        printf("\033[32m[%s][Xkore3] listener thread started\033[0m\n\n", ts);
    }
}

// ============================================================
//  ForwardToXkore3
//  Wraps a RO packet in a 4-byte frame header and sends it to Xkore3.
//
//  Frame: [dir(1)] [0x00(1)] [len_lo(1)] [len_hi(1)] [payload...]
//  dir 0x01 = C->S,  0x02 = S->C
// ============================================================

static void ForwardToXkore3(BYTE direction, const char* buf, int len) {
    if (!g_xkConnected || g_xkSocket == INVALID_SOCKET || len <= 0) return;

    int    frameSize = 4 + len;
    BYTE*  frame     = (BYTE*)malloc(frameSize);
    if (!frame) return;

    frame[0] = direction;
    frame[1] = 0x00;
    frame[2] = (BYTE)( len       & 0xFF);
    frame[3] = (BYTE)((len >> 8) & 0xFF);
    memcpy(frame + 4, buf, len);

    typedef int (WSAAPI* raw_send_t)(SOCKET, const char*, int, int);
    static raw_send_t s_rawSend = nullptr;
    if (!s_rawSend)
        s_rawSend = (raw_send_t)GetProcAddress(GetModuleHandleA("ws2_32.dll"), "send");

    if (!s_rawSend) { free(frame); return; }

    if (s_rawSend(g_xkSocket, (const char*)frame, frameSize, 0) == SOCKET_ERROR) {
        printf("\033[31m[Xkore3] forward failed err=%d\033[0m\n", WSAGetLastError());
        g_xkConnected  = false;
        g_redirectReady = false;
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
    }

    free(frame);
}

// ============================================================
//  InjectQueue_Push  (called by listener thread)
//  Returns false if queue is full (packet dropped).
// ============================================================

static bool InjectQueue_Push(const BYTE* data, int len) {
    if (len <= 0 || len > INJECT_PKT_MAXLEN) {
        printf("\033[31m[Queue] Push rejected: len=%d out of range\033[0m\n", len);
        return false;
    }

    EnterCriticalSection(&g_qLock);

    int next = (g_qTail + 1) % INJECT_QUEUE_SIZE;
    if (next == g_qHead) {   // queue full
        LeaveCriticalSection(&g_qLock);
        printf("\033[31m[Queue] full — inject packet len=%d dropped\033[0m\n", len);
        return false;
    }

    memcpy(g_injectQueue[g_qTail].data, data, len);
    g_injectQueue[g_qTail].len = len;
    g_qTail = next;

    LeaveCriticalSection(&g_qLock);
    return true;
}

// ============================================================
//  InjectQueue_Pop  (called by MyRecvHook on game thread)
//  Returns bytes copied, 0 if empty, -1 if packet exceeds bufMaxLen.
// ============================================================

static int InjectQueue_Pop(char* outBuf, int bufMaxLen) {
    EnterCriticalSection(&g_qLock);

    if (g_qHead == g_qTail) {   // queue empty
        LeaveCriticalSection(&g_qLock);
        return 0;
    }

    int pktLen = g_injectQueue[g_qHead].len;
    if (pktLen > bufMaxLen) {
        g_qHead = (g_qHead + 1) % INJECT_QUEUE_SIZE;   // discard oversized packet
        LeaveCriticalSection(&g_qLock);
        printf("\033[31m[Queue] Pop skip: len=%d > bufMax=%d\033[0m\n", pktLen, bufMaxLen);
        return -1;
    }

    memcpy(outBuf, g_injectQueue[g_qHead].data, pktLen);
    g_qHead = (g_qHead + 1) % INJECT_QUEUE_SIZE;

    LeaveCriticalSection(&g_qLock);
    return pktLen;
}

// ============================================================
//  MySendHook — intercepts ws2_32!send
//
//  Flow:
//    skip own xkore socket → cache Gepard identity (len=269)
//    → pass-through Gepard packets unchanged
//    → on real LOGIN_REQ (0x0064 len=55 non-zero): ConnectXkore3
//    → log + forward non-Gepard packets to Xkore3
//    → trampoline: unhook → call original send → re-hook
// ============================================================

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {

    if (s == g_xkSocket) goto send_normal;  // never intercept our own Xkore3 socket
    if (len < 2)          goto send_normal;

    {
        unsigned short op = *(unsigned short*)buf;

        // Cache Gepard identity packet (first occurrence only)
        if (len == GEPARD_IDENTITY_LEN && !g_gepardCached) {
            memcpy(g_gepardCache, buf, len);
            g_gepardCachedLen = len;
            g_gepardCached    = true;
            g_gepardSocket    = s;
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[32m[%s][Gepard] identity cached (%d bytes)\033[0m\n", ts, len);
        }

        // Gepard packets → send directly to RO server, never to Xkore3
        if (IsGepardPacket(buf, len)) {
            PrintPacket("C->S[GEP]", buf, len);
            WriteLog("C->S", buf, len);
            goto send_normal;
        }

        // First real LOGIN_REQ → trigger Xkore3 connection
        if (op == 0x0064 && len == 55) {
            bool allZero = true;
            for (int i = 4; i < len && allZero; i++)
                if ((unsigned char)buf[i] != 0x00) allZero = false;

            if (!allZero && !g_redirectReady) {
                char ts[16]; FormatTimestamp(ts, sizeof(ts));
                printf("\033[35m[%s][Redirect] real LOGIN_REQ detected → connecting Xkore3\033[0m\n", ts);
                ConnectXkore3();
            }
        }

        PrintPacket("C->S", buf, len);
        WriteLog("C->S", buf, len);

        if (g_redirectReady)
            ForwardToXkore3(0x01, buf, len);
    }

send_normal:
    {
        DWORD old;
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(pOriginalSend, origSendBytes, 5);                        // remove JMP (unhook)
        int res = pOriginalSend(s, buf, len, flags);                    // call real send()
        BYTE jmp[5] = { 0xE9 };
        *(DWORD*)(jmp + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
        memcpy(pOriginalSend, jmp, 5);                                  // re-hook
        VirtualProtect(pOriginalSend, 5, old, &old);
        return res;
    }
}

// ============================================================
//  MyRecvHook — intercepts ws2_32!recv
//
//  Flow:
//    if redirect active → check inject queue first
//      → inject packet found: return it to game immediately
//    → trampoline to real recv()
//    → filter GEPARD_SECURITY_SEED (0x4753): pass to game only
//    → log + forward S->C packets to Xkore3
// ============================================================

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {

    // Drain inject queue before blocking on real recv
    if (g_redirectReady) {
        int injected = InjectQueue_Pop(buf, len);
        if (injected > 0) {
            unsigned short op = *(unsigned short*)buf;
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[35m[%s][Inject] delivered OP:0x%04X (%s) Len:%d\033[0m\n",
                   ts, op, GetOpName(op), injected);
            WriteLog("S->C[INJ]", buf, injected);
            return injected;
        }
    }

    // Trampoline: call real recv()
    DWORD old;
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pOriginalRecv, origRecvBytes, 5);                            // unhook
    int res = pOriginalRecv(s, buf, len, flags);                        // real recv()
    BYTE jmp[5] = { 0xE9 };
    *(DWORD*)(jmp + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmp, 5);                                      // re-hook
    VirtualProtect(pOriginalRecv, 5, old, &old);

    if (res <= 0) return res;

    if (res >= 2) {
        unsigned short op = *(unsigned short*)buf;

        // Gepard seed: game handles this internally, never forward to Xkore3
        if (op == 0x4753) {
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[32m[%s][Gepard] SECURITY_SEED (0x4753) Len:%d — client handles\033[0m\n",
                   ts, res);
            WriteLog("S->C", buf, res);
            return res;
        }

        PrintPacket("S->C", buf, res);
        WriteLog("S->C", buf, res);

        if (g_redirectReady)
            ForwardToXkore3(0x02, buf, res);
    }

    return res;
}

// ============================================================
//  StartHooking — patches ws2_32!send and ws2_32!recv
//  with 5-byte relative JMP trampolines.
// ============================================================

void StartHooking() {
    InitConsole();

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

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)StartHooking, nullptr, 0, nullptr);
    }
    return TRUE;
}
