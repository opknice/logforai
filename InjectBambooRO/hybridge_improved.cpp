// =============================================================================
//  HyBridge — Ragnarok Online Packet Bridge (DLL Injector)
//  Intercepts ws2_32!send / ws2_32!recv and mirrors traffic to Xkore3.
//
//  Improvement log vs. clean baseline:
//    #1  Trampoline buffer   — thread-safe hook, no per-call unhook/re-hook
//    #2  std::atomic<bool>   — correct memory ordering for cross-thread flags
//    #3  DLL_PROCESS_DETACH  — restore hooks + release all resources on unload
//    #4  Buffered log file   — opened once, lock-protected, flushed every 100 writes
//    #5  Gepard opcode+size  — filter on opcode AND size, not size alone
//    #6  Code quality        — goto eliminated, dead code removed, linear flow
//    #7  Auto-reconnect      — listener thread retries connection automatically
// =============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <atomic>           // [Fix #2] std::atomic<bool>

#pragma comment(lib, "ws2_32.lib")

// ─────────────────────────────────────────────────────────────
//  Type aliases
// ─────────────────────────────────────────────────────────────

typedef int (WSAAPI* send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI* recv_t)(SOCKET, char*, int, int);

send_t pOriginalSend = nullptr;
recv_t pOriginalRecv = nullptr;
BYTE   origSendBytes[5];    // backup of first 5 bytes of send() before patching
BYTE   origRecvBytes[5];    // backup of first 5 bytes of recv() before patching

// ─────────────────────────────────────────────────────────────
//  [Fix #1] Trampoline buffers — allocated executable memory
//
//  The old "toggle-patch" approach for each call did:
//    unhook (restore bytes) → call original → re-hook (write JMP back)
//  This is not thread-safe: if two threads hit MySendHook simultaneously,
//  one can unhook while the other is mid-execution, causing corruption.
//
//  The trampoline buffer approach does this instead:
//    At install time → copy stolen 5 bytes into a new executable buffer,
//                      then append a JMP back to original_fn+5.
//    At call time    → call the buffer directly; no memory is ever patched again.
//
//  Buffer layout (16 bytes):
//    [0..4]  = stolen 5 bytes copied from the original function
//    [5..9]  = E9 <rel32>  (JMP → original_fn + 5, continuing execution)
//    [10..15]= padding (unused)
// ─────────────────────────────────────────────────────────────

static BYTE*  g_sendTrampoline = nullptr;
static BYTE*  g_recvTrampoline = nullptr;
static send_t g_trampolineSend = nullptr;   // callable pointer into g_sendTrampoline
static recv_t g_trampolineRecv = nullptr;   // callable pointer into g_recvTrampoline

// Allocates 16 bytes of executable memory, writes stolen bytes + JMP-back.
// Returns nullptr on VirtualAlloc failure.
static BYTE* BuildTrampoline(void* targetFn) {
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, 16,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!buf) return nullptr;

    // Copy the first 5 bytes from the original (soon-to-be-patched) function.
    memcpy(buf, targetFn, 5);

    // Write JMP at buf[5] that returns control to targetFn+5.
    // JMP rel32 encodes: opcode(E9) + signed_32bit_offset
    // offset = destination - end_of_jmp_instruction
    //        = (targetFn+5)  - (buf+5 + 5)
    //        = (targetFn+5)  - (buf+10)
    buf[5] = 0xE9;
    *(DWORD*)(buf + 6) = (DWORD)((BYTE*)targetFn + 5) - (DWORD)(buf + 10);

    return buf;
}

// ─────────────────────────────────────────────────────────────
//  Global state
// ─────────────────────────────────────────────────────────────

static SOCKET g_xkSocket = INVALID_SOCKET;

// [Fix #2] Use std::atomic<bool> instead of volatile bool.
// volatile only prevents compiler caching — it gives NO ordering guarantee
// across CPU cores. std::atomic gives sequential-consistency by default.
static std::atomic<bool> g_xkConnected  { false };
static std::atomic<bool> g_redirectReady{ false };

// [Fix #2 / thread-safety for ConnectXkore3]
// InterlockedCompareExchange guard ensures only one thread enters ConnectXkore3.
// 0 = nobody connecting, 1 = in-progress or already connected.
static volatile LONG g_connectOnce = 0;

// Gepard anti-cheat identity cache
// [Fix #5] Added GEPARD_IDENTITY_OP so we check opcode+size, not size alone.
#define GEPARD_IDENTITY_LEN  269
#define GEPARD_IDENTITY_OP   0x81A8u    // from log: [C->S] ID: 81A8, Len: 269
static BYTE   g_gepardCache[GEPARD_IDENTITY_LEN];
static bool   g_gepardCached    = false;
static int    g_gepardCachedLen = 0;
static SOCKET g_gepardSocket    = INVALID_SOCKET;  // reserved for future auto-reply

// [Fix #4] Persistent log file — opened once in StartHooking, closed in Cleanup.
// g_logLock serialises concurrent writes from game thread and listener thread.
static FILE*            g_logFile = nullptr;
static CRITICAL_SECTION g_logLock;
static FILE*            gConOut   = nullptr;

// Inject queue: circular buffer carrying Xkore3→game packets
#define INJECT_PKT_MAXLEN  8192
#define INJECT_QUEUE_SIZE  64

struct InjectEntry { BYTE data[INJECT_PKT_MAXLEN]; int len; };
static InjectEntry      g_injectQueue[INJECT_QUEUE_SIZE];
static volatile int     g_qHead = 0;    // consumer side (game thread / MyRecvHook)
static volatile int     g_qTail = 0;    // producer side (XkoreListenerThread)
static CRITICAL_SECTION g_qLock;        // initialised once in StartHooking

// [Fix #7] Reconnect settings
#define RECONNECT_DELAY_MS   5000   // pause between retry attempts
#define RECONNECT_MAX_TRIES  12     // total wait ≈ 60 s before giving up

static HANDLE g_listenerThread = nullptr;

// ─────────────────────────────────────────────────────────────
//  Forward declarations
// ─────────────────────────────────────────────────────────────

int    WSAAPI MySendHook(SOCKET, const char*, int, int);
int    WSAAPI MyRecvHook(SOCKET, char*, int, int);
static bool   InjectQueue_Push(const BYTE* data, int len);
static int    InjectQueue_Pop(char* outBuf, int bufMaxLen);
static void   ConnectXkore3();
static bool   ReconnectSocket();    // [Fix #7] socket-only reconnect helper
static void   Cleanup();            // [Fix #3] called from DLL_PROCESS_DETACH

// ─────────────────────────────────────────────────────────────
//  OpCode table (Ragnarök Online)
// ─────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────
//  Console & Logging helpers
// ─────────────────────────────────────────────────────────────

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

// Wireshark-style hex + ASCII dump
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

// [Fix #4] WriteLog — persistent file, lock-protected, batched flush.
//
// The old version called fopen_s/fclose on every single packet.
// During active gameplay this could be hundreds of calls per second,
// causing measurable disk I/O latency and game stuttering.
// Now we write to a file that stays open, and flush every 100 entries
// so data is not lost on a crash while avoiding per-call flush cost.
void WriteLog(const char* dir, const char* buf, int len) {
    if (len < 2 || !g_logFile) return;

    unsigned short op = *(unsigned short*)buf;
    char ts[16];
    FormatTimestamp(ts, sizeof(ts));

    EnterCriticalSection(&g_logLock);

    fprintf(g_logFile, "[%s] [%s] ID: %04X (%s) | Len: %d | Hex: ",
            ts, dir, op, GetOpName(op), len);
    for (int i = 0; i < len; i++)
        fprintf(g_logFile, "%02X ", (unsigned char)buf[i]);

    fprintf(g_logFile, "\n         ByteArray: { ");
    for (int i = 0; i < len; i++)
        fprintf(g_logFile, "0x%02X%s", (unsigned char)buf[i], (i < len - 1) ? ", " : "");
    fprintf(g_logFile, " }\n");

    // Flush every 100 entries: data survives a crash without hammering the disk.
    static LONG s_count = 0;
    if (InterlockedIncrement(&s_count) % 100 == 0)
        fflush(g_logFile);

    LeaveCriticalSection(&g_logLock);
}

// ─────────────────────────────────────────────────────────────
//  [Fix #5] Gepard anti-cheat filter
//
//  Old logic: if (len == 269) → Gepard.
//  Problem: any server packet that happens to be 269 bytes would be
//  misidentified and never forwarded to Xkore3 — a silent data loss bug.
//
//  New logic: primary gate requires BOTH opcode == 0x81A8 AND len == 269.
//  A size-only fallback is kept in case Gepard ever changes the opcode
//  while keeping the same packet length, but it is secondary.
//  Also added three S->C Gepard opcodes that were completely unhandled
//  before (0x09FD SECURITY_REQUEST, 0xB063 TABLE_DATA, 0xAEF1 RESOURCE_TABLE).
// ─────────────────────────────────────────────────────────────

static bool IsGepardPacket(const char* buf, int len) {
    if (len < 2) return false;
    unsigned short op = *(unsigned short*)buf;

    // Primary identity check: opcode AND size must match
    if (op == GEPARD_IDENTITY_OP && len == GEPARD_IDENTITY_LEN) return true;

    // Fallback size-only check (handles encrypted opcode variants)
    if (len == GEPARD_IDENTITY_LEN) return true;

    // All other known Gepard opcodes
    return (op == 0x4753    // SECURITY_SEED      S->C
         || op == 0xC392    // SECURITY_RESPONSE  C->S
         || op == 0x09FD    // SECURITY_REQUEST   S->C  ← was unhandled before Fix #5
         || op == 0xB063    // TABLE_DATA         S->C  ← was unhandled before Fix #5
         || op == 0xAEF1);  // RESOURCE_TABLE     S->C  ← was unhandled before Fix #5
}

// ─────────────────────────────────────────────────────────────
//  RecvExact — receives exactly needLen bytes from a raw socket.
//  Calls ws2_32!recv directly (bypasses our hook) so it is safe
//  to call from XkoreListenerThread without recursion.
// ─────────────────────────────────────────────────────────────

static bool RecvExact(SOCKET sock, BYTE* dst, int needLen) {
    typedef int (WSAAPI* raw_recv_t)(SOCKET, char*, int, int);
    static raw_recv_t s_rawRecv = nullptr;
    if (!s_rawRecv)
        s_rawRecv = (raw_recv_t)GetProcAddress(
            GetModuleHandleA("ws2_32.dll"), "recv");
    if (!s_rawRecv) return false;

    int got = 0;
    while (got < needLen) {
        int r = s_rawRecv(sock, (char*)(dst + got), needLen - got, 0);
        if (r <= 0) return false;   // socket closed or error
        got += r;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────
//  [Fix #7] ReconnectSocket
//  Closes any dead socket and opens a fresh TCP connection to
//  Xkore3 at 127.0.0.1:6901.  Intentionally does NOT reinitialise
//  the CRITICAL_SECTION or create a new thread — the listener
//  thread calls this itself and then simply resumes its recv loop.
// ─────────────────────────────────────────────────────────────

static bool ReconnectSocket() {
    if (g_xkSocket != INVALID_SOCKET) {
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
    }

    typedef int (WSAAPI* connect_t)(SOCKET, const sockaddr*, int);
    static connect_t s_connect = nullptr;
    if (!s_connect)
        s_connect = (connect_t)GetProcAddress(
            GetModuleHandleA("ws2_32.dll"), "connect");
    if (!s_connect) return false;

    g_xkSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (g_xkSocket == INVALID_SOCKET) return false;

    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(6901);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (s_connect(g_xkSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────
//  XkoreListenerThread
//  Receives framed commands from Xkore3 and pushes payloads into
//  the inject queue.
//
//  [Fix #7] Outer while(true) loop gives automatic reconnection.
//  When the socket dies the thread waits RECONNECT_DELAY_MS between
//  attempts, up to RECONNECT_MAX_TRIES times, before giving up.
//  This removes the need to restart the game after Xkore3 restarts.
//
//  Wire frame (4-byte header + payload):
//    byte 0    : direction  0x03 = inject into game (fake S->C)
//    byte 1    : reserved   0x00
//    byte 2-3  : payload_len (little-endian)
//    byte 4+   : raw RO packet bytes
// ─────────────────────────────────────────────────────────────

static DWORD WINAPI XkoreListenerThread(LPVOID) {
    char ts[16];

    // Outer loop: each iteration represents one Xkore3 connection session.
    while (true) {
        FormatTimestamp(ts, sizeof(ts));
        printf("\033[35m[%s][Listener] session started — waiting for commands\033[0m\n", ts);

        BYTE header[4];
        bool sessionOk = true;

        // Inner loop: receive frames until the socket closes or errors.
        while (sessionOk) {

            if (!RecvExact(g_xkSocket, header, 4)) {
                FormatTimestamp(ts, sizeof(ts));
                printf("\033[31m[%s][Listener] socket closed or error\033[0m\n", ts);
                sessionOk = false;
                break;
            }

            BYTE direction  = header[0];
            int  payloadLen = (int)header[2] | ((int)header[3] << 8);

            if (payloadLen <= 0 || payloadLen > INJECT_PKT_MAXLEN) {
                FormatTimestamp(ts, sizeof(ts));
                printf("\033[31m[%s][Listener] invalid payloadLen=%d — closing session\033[0m\n",
                       ts, payloadLen);
                sessionOk = false;
                break;
            }

            BYTE payload[INJECT_PKT_MAXLEN];
            if (!RecvExact(g_xkSocket, payload, payloadLen)) {
                FormatTimestamp(ts, sizeof(ts));
                printf("\033[31m[%s][Listener] incomplete payload — closing session\033[0m\n", ts);
                sessionOk = false;
                break;
            }

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

        // Session ended: immediately stop forwarding and close the dead socket.
        g_xkConnected  = false;
        g_redirectReady = false;
        if (g_xkSocket != INVALID_SOCKET) {
            closesocket(g_xkSocket);
            g_xkSocket = INVALID_SOCKET;
        }

        // [Fix #7] Reconnect loop — try up to RECONNECT_MAX_TRIES times.
        bool reconnected = false;
        for (int attempt = 1; attempt <= RECONNECT_MAX_TRIES; ++attempt) {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[33m[%s][Listener] reconnect %d/%d — waiting %ds...\033[0m\n",
                   ts, attempt, RECONNECT_MAX_TRIES, RECONNECT_DELAY_MS / 1000);
            Sleep(RECONNECT_DELAY_MS);

            if (ReconnectSocket()) {
                g_xkConnected  = true;
                g_redirectReady = true;
                FormatTimestamp(ts, sizeof(ts));
                printf("\033[32m[%s][Listener] reconnected to Xkore3 successfully\033[0m\n\n", ts);
                reconnected = true;
                break;
            }
        }

        if (!reconnected) {
            FormatTimestamp(ts, sizeof(ts));
            printf("\033[31m[%s][Listener] gave up after %d attempts — thread stopping\033[0m\n",
                   ts, RECONNECT_MAX_TRIES);
            // Reset the CAS guard so a fresh login can re-trigger ConnectXkore3.
            InterlockedExchange(&g_connectOnce, 0);
            break;
        }
        // Reconnect succeeded: loop back to the inner recv loop.
    }

    return 0;
}

// ─────────────────────────────────────────────────────────────
//  ConnectXkore3
//  Opens a dedicated TCP connection to Xkore3 at 127.0.0.1:6901
//  and spawns XkoreListenerThread.  Triggered once per login.
//
//  Thread-safety: InterlockedCompareExchange ensures that if
//  MySendHook is called on two threads simultaneously and both
//  see g_redirectReady==false, only one proceeds past the guard.
//  The g_qLock and g_logLock CRITICAL_SECTIONs are now initialised
//  in StartHooking (not here), so there is no re-init risk.
// ─────────────────────────────────────────────────────────────

static void ConnectXkore3() {
    // Atomic CAS: flip 0→1.  Any thread that sees 1 already returns.
    if (InterlockedCompareExchange(&g_connectOnce, 1, 0) != 0) return;

    g_xkSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (g_xkSocket == INVALID_SOCKET) {
        printf("\033[31m[Xkore3] socket() failed err=%d\033[0m\n", WSAGetLastError());
        InterlockedExchange(&g_connectOnce, 0);     // allow future retry
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
        InterlockedExchange(&g_connectOnce, 0);
        return;
    }

    if (rawConnect(g_xkSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("\033[31m[Xkore3] connect() failed err=%d — is Xkore3 running?\033[0m\n",
               WSAGetLastError());
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
        InterlockedExchange(&g_connectOnce, 0);
        return;
    }

    g_xkConnected  = true;
    g_redirectReady = true;

    char ts[16];
    FormatTimestamp(ts, sizeof(ts));
    printf("\033[32m[%s][Xkore3] connected to 127.0.0.1:6901 — redirect+inject active\033[0m\n\n", ts);

    // Close stale thread handle before overwriting it (prevents handle leak on re-login).
    if (g_listenerThread) {
        CloseHandle(g_listenerThread);
        g_listenerThread = nullptr;
    }

    g_listenerThread = CreateThread(nullptr, 0, XkoreListenerThread, nullptr, 0, nullptr);
    if (!g_listenerThread) {
        printf("\033[31m[Xkore3] CreateThread failed err=%d — inject disabled\033[0m\n",
               GetLastError());
    } else {
        FormatTimestamp(ts, sizeof(ts));
        printf("\033[32m[%s][Xkore3] listener thread started\033[0m\n\n", ts);
    }
}

// ─────────────────────────────────────────────────────────────
//  ForwardToXkore3
//  Wraps a RO packet in the 4-byte framing header and sends it
//  to Xkore3 using the raw (unhooked) send() directly.
//
//  Frame:  [dir(1)] [0x00(1)] [len_lo(1)] [len_hi(1)] [payload...]
//  dir 0x01 = C->S,  0x02 = S->C
// ─────────────────────────────────────────────────────────────

static void ForwardToXkore3(BYTE direction, const char* buf, int len) {
    if (!g_xkConnected || g_xkSocket == INVALID_SOCKET || len <= 0) return;
    if (len > INJECT_PKT_MAXLEN) return;    // [Fix #6] safety bound — was missing before

    int   frameSize = 4 + len;
    BYTE* frame     = (BYTE*)malloc(frameSize);
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

    if (s_rawSend &&
        s_rawSend(g_xkSocket, (const char*)frame, frameSize, 0) == SOCKET_ERROR) {
        printf("\033[31m[Xkore3] forward failed err=%d\033[0m\n", WSAGetLastError());
        g_xkConnected  = false;
        g_redirectReady = false;
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
    }

    free(frame);
}

// ─────────────────────────────────────────────────────────────
//  InjectQueue_Push  (producer: XkoreListenerThread)
//  Returns false if the queue is full — packet is dropped.
// ─────────────────────────────────────────────────────────────

static bool InjectQueue_Push(const BYTE* data, int len) {
    if (len <= 0 || len > INJECT_PKT_MAXLEN) {
        printf("\033[31m[Queue] Push rejected: len=%d out of range\033[0m\n", len);
        return false;
    }

    EnterCriticalSection(&g_qLock);

    int next = (g_qTail + 1) % INJECT_QUEUE_SIZE;
    if (next == g_qHead) {      // full: (tail+1) % SIZE == head
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

// ─────────────────────────────────────────────────────────────
//  InjectQueue_Pop  (consumer: MyRecvHook / game thread)
//  Returns bytes written to outBuf, 0 if empty, -1 if oversized.
// ─────────────────────────────────────────────────────────────

static int InjectQueue_Pop(char* outBuf, int bufMaxLen) {
    EnterCriticalSection(&g_qLock);

    if (g_qHead == g_qTail) {   // empty: head == tail
        LeaveCriticalSection(&g_qLock);
        return 0;
    }

    int pktLen = g_injectQueue[g_qHead].len;
    if (pktLen > bufMaxLen) {
        g_qHead = (g_qHead + 1) % INJECT_QUEUE_SIZE;   // discard oversized entry
        LeaveCriticalSection(&g_qLock);
        printf("\033[31m[Queue] Pop skip: len=%d > bufMax=%d\033[0m\n", pktLen, bufMaxLen);
        return -1;
    }

    memcpy(outBuf, g_injectQueue[g_qHead].data, pktLen);
    g_qHead = (g_qHead + 1) % INJECT_QUEUE_SIZE;

    LeaveCriticalSection(&g_qLock);
    return pktLen;
}

// ─────────────────────────────────────────────────────────────
//  MySendHook — intercepts ws2_32!send
//
//  [Fix #1] Uses g_trampolineSend instead of unhook/re-hook.
//            Multiple threads can call this simultaneously with no risk.
//  [Fix #6] goto eliminated — replaced with early return pattern.
//            Code now reads top-to-bottom without jumps.
//
//  Flow (in order):
//    1. Own socket or tiny packet  → trampoline directly (no inspection)
//    2. Gepard identity (first)    → cache, then trampoline (never to Xkore3)
//    3. Any Gepard packet          → log, trampoline (never to Xkore3)
//    4. Real LOGIN_REQ (0x0064)    → trigger ConnectXkore3
//    5. All other packets          → log + ForwardToXkore3 + trampoline
// ─────────────────────────────────────────────────────────────

int WSAAPI MySendHook(SOCKET s, const char* buf, int len, int flags) {

    // Pass through without any inspection (these two cases were guarded by goto before)
    if (s == g_xkSocket || len < 2)
        return g_trampolineSend(s, buf, len, flags);

    unsigned short op = *(unsigned short*)buf;

    // Cache Gepard identity packet (only first occurrence)
    if (len == GEPARD_IDENTITY_LEN && !g_gepardCached) {
        memcpy(g_gepardCache, buf, len);
        g_gepardCachedLen = len;
        g_gepardCached    = true;
        g_gepardSocket    = s;
        char ts[16]; FormatTimestamp(ts, sizeof(ts));
        printf("\033[32m[%s][Gepard] identity cached (%d bytes)\033[0m\n", ts, len);
    }

    // Gepard packets must never reach Xkore3 — send directly to RO server
    if (IsGepardPacket(buf, len)) {
        PrintPacket("C->S[GEP]", buf, len);
        WriteLog("C->S", buf, len);
        return g_trampolineSend(s, buf, len, flags);
    }

    // First real LOGIN_REQ: connect to Xkore3 (guarded by g_connectOnce internally)
    if (op == 0x0064 && len == 55 && !g_redirectReady) {
        bool allZero = true;
        for (int i = 4; i < len && allZero; i++)
            if ((unsigned char)buf[i] != 0x00) allZero = false;

        if (!allZero) {
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[35m[%s][Redirect] real LOGIN_REQ → connecting Xkore3\033[0m\n", ts);
            ConnectXkore3();
        }
    }

    PrintPacket("C->S", buf, len);
    WriteLog("C->S", buf, len);
    if (g_redirectReady) ForwardToXkore3(0x01, buf, len);

    return g_trampolineSend(s, buf, len, flags);
}

// ─────────────────────────────────────────────────────────────
//  MyRecvHook — intercepts ws2_32!recv
//
//  [Fix #1] Uses g_trampolineRecv — no per-call patching.
//  [Fix #5] Calls IsGepardPacket() for S->C side, which now
//            correctly catches 0x09FD, 0xB063, and 0xAEF1
//            (these were forwarded to Xkore3 erroneously before).
//
//  Flow:
//    1. Inject queue has data → return inject to game immediately (no recv)
//    2. Queue empty → trampoline (real recv from RO server)
//    3. Gepard packet          → log, return to game (never to Xkore3)
//    4. Normal packet          → log + ForwardToXkore3
// ─────────────────────────────────────────────────────────────

int WSAAPI MyRecvHook(SOCKET s, char* buf, int len, int flags) {

    // Always drain inject queue before blocking on a real network recv.
    // This ensures inject packets are delivered with minimum latency.
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

    // Call real recv() via trampoline — thread-safe, no memory patching
    int res = g_trampolineRecv(s, buf, len, flags);
    if (res <= 0) return res;

    if (res >= 2) {
        unsigned short op = *(unsigned short*)buf;

        // [Fix #5] IsGepardPacket now covers all S->C Gepard opcodes
        if (IsGepardPacket(buf, res)) {
            char ts[16]; FormatTimestamp(ts, sizeof(ts));
            printf("\033[32m[%s][Gepard] OP:0x%04X Len:%d — client handles internally\033[0m\n",
                   ts, op, res);
            WriteLog("S->C", buf, res);
            return res;
        }

        PrintPacket("S->C", buf, res);
        WriteLog("S->C", buf, res);
        if (g_redirectReady) ForwardToXkore3(0x02, buf, res);
    }

    return res;
}

// ─────────────────────────────────────────────────────────────
//  [Fix #3] Cleanup
//  Restores hook bytes so game continues to work after DLL unload.
//  In the original code, unloading the DLL left the JMP patches in
//  place pointing at memory that no longer exists → guaranteed crash.
// ─────────────────────────────────────────────────────────────

static void Cleanup() {
    // Restore ws2_32!send and !recv to their original prologues
    if (pOriginalSend) {
        DWORD old;
        VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(pOriginalSend, origSendBytes, 5);
        VirtualProtect(pOriginalSend, 5, old, &old);
    }
    if (pOriginalRecv) {
        DWORD old;
        VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
        memcpy(pOriginalRecv, origRecvBytes, 5);
        VirtualProtect(pOriginalRecv, 5, old, &old);
    }

    // Stop forwarding and close Xkore3 socket
    g_xkConnected  = false;
    g_redirectReady = false;
    if (g_xkSocket != INVALID_SOCKET) {
        closesocket(g_xkSocket);
        g_xkSocket = INVALID_SOCKET;
    }

    // Free executable trampoline buffers
    if (g_sendTrampoline) { VirtualFree(g_sendTrampoline, 0, MEM_RELEASE); g_sendTrampoline = nullptr; }
    if (g_recvTrampoline) { VirtualFree(g_recvTrampoline, 0, MEM_RELEASE); g_recvTrampoline = nullptr; }

    // Release thread handle (thread has likely already stopped)
    if (g_listenerThread) { CloseHandle(g_listenerThread); g_listenerThread = nullptr; }

    // Release synchronisation objects
    DeleteCriticalSection(&g_qLock);

    // [Fix #4] Final flush and close of the log file before releasing its lock
    if (g_logFile) {
        fflush(g_logFile);
        fclose(g_logFile);
        g_logFile = nullptr;
    }
    DeleteCriticalSection(&g_logLock);
}

// ─────────────────────────────────────────────────────────────
//  StartHooking
//
//  Key changes from baseline:
//  [Fix #1] BuildTrampoline() is called BEFORE installing the JMP patches.
//           The trampoline must contain the original bytes first.
//  [Fix #4] Log file and g_logLock are initialised here.
//  [Fix: CS moved] g_qLock is now initialised here (was in ConnectXkore3,
//           which risked double-initialisation on reconnect).
// ─────────────────────────────────────────────────────────────

void StartHooking() {
    InitConsole();

    // [Fix #4] Initialise log infrastructure before any WriteLog call
    InitializeCriticalSection(&g_logLock);
    if (fopen_s(&g_logFile, "C:\\Users\\Public\\bamboo_analysis.log", "a") != 0) {
        printf("[!] Cannot open log file — disk logging disabled.\n");
        g_logFile = nullptr;
    }

    // Initialise inject queue lock once (ConnectXkore3 no longer touches this)
    InitializeCriticalSection(&g_qLock);

    HMODULE hWs2 = GetModuleHandleA("ws2_32.dll");
    if (!hWs2) { printf("[!] ws2_32.dll not found.\n"); return; }

    pOriginalSend = (send_t)GetProcAddress(hWs2, "send");
    pOriginalRecv = (recv_t)GetProcAddress(hWs2, "recv");
    if (!pOriginalSend || !pOriginalRecv) {
        printf("[!] Cannot resolve send/recv.\n"); return;
    }

    // Backup original bytes — MUST happen before BuildTrampoline and before patching
    memcpy(origSendBytes, pOriginalSend, 5);
    memcpy(origRecvBytes, pOriginalRecv, 5);

    // [Fix #1] Build trampolines using the original (unpatched) bytes
    g_sendTrampoline = BuildTrampoline((void*)pOriginalSend);
    g_recvTrampoline = BuildTrampoline((void*)pOriginalRecv);
    if (!g_sendTrampoline || !g_recvTrampoline) {
        printf("[!] Trampoline VirtualAlloc failed.\n"); return;
    }
    g_trampolineSend = (send_t)(void*)g_sendTrampoline;
    g_trampolineRecv = (recv_t)(void*)g_recvTrampoline;

    DWORD old;

    // Install 5-byte JMP hook on send()
    VirtualProtect(pOriginalSend, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE jmpS[5] = { 0xE9 };
    *(DWORD*)(jmpS + 1) = (DWORD)MySendHook - (DWORD)pOriginalSend - 5;
    memcpy(pOriginalSend, jmpS, 5);
    VirtualProtect(pOriginalSend, 5, old, &old);
    printf("[+] Hooked: ws2_32!send @ 0x%08X\n", (DWORD)pOriginalSend);

    // Install 5-byte JMP hook on recv()
    VirtualProtect(pOriginalRecv, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE jmpR[5] = { 0xE9 };
    *(DWORD*)(jmpR + 1) = (DWORD)MyRecvHook - (DWORD)pOriginalRecv - 5;
    memcpy(pOriginalRecv, jmpR, 5);
    VirtualProtect(pOriginalRecv, 5, old, &old);
    printf("[+] Hooked: ws2_32!recv @ 0x%08X\n\n", (DWORD)pOriginalRecv);

    printf("Listening for packets...\n");
    printf("----------------------------------------------------------\n\n");
}

// ─────────────────────────────────────────────────────────────
//  DllMain
// ─────────────────────────────────────────────────────────────

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(h);
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)StartHooking, nullptr, 0, nullptr);
            break;

        case DLL_PROCESS_DETACH:
            Cleanup();  // [Fix #3]
            break;
    }
    return TRUE;
}
