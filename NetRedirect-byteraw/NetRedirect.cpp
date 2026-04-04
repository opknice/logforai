// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include "pch.h"
#include "NetRedirect.h"
#include "Common.h"

// load Microsoft Detour Lib
#include "detours.h"
#pragma comment(lib, "detours.lib")

#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <mutex>

HMODULE hModule;
HANDLE hThread;
bool keepMainThread = true;

// Connection to the X-Kore server that Kore created
static SOCKET koreClient = INVALID_SOCKET;
static bool koreClientIsAlive = false;
static SOCKET roServer = INVALID_SOCKET;
static string roSendBuf("");	// Data to send to the RO client
static string xkoreSendBuf("");	// Data to send to the X-Kore server


// แทนที่ roServer ตัวเดียว ด้วย 2 ตัวแยกชัดเจน
static SOCKET roGameSocket = INVALID_SOCKET;  // RO Protocol socket (packet 0x0065 ฯลฯ)
static SOCKET roHttpSocket = INVALID_SOCKET;  // HTTP socket (POST /userconfig ฯลฯ)
bool imalive = false;

// ─────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────
static std::mutex logMutex;
static const char* LOG_FILE = "NetRedirect.log";
static const char* SEPARATOR = "\n";

static std::string getCurrentTime()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

/**
 * logPacket
 *   direction : "[C->S]"  หรือ  "[S->C]"
 *   buffer    : raw bytes
 *   len       : จำนวน bytes
 *
 * Format:
 *   [HH:MM:SS] [C->S] ID: XXXX | Len: N | Hex: XX XX XX ...
 *   ByteArray: { 0xXX, 0xXX, ... }
 *   ########...
 */
static void logPacket(const char* buffer, int len, const char* direction)
{
    if (len <= 0) return;

    std::lock_guard<std::mutex> lock(logMutex);

    std::ofstream ofs(LOG_FILE, std::ios::app);
    if (!ofs.is_open()) return;

    // Packet ID = first 2 bytes (little-endian)
    unsigned short packetID = 0;
    if (len >= 2)
        packetID = (unsigned char)buffer[0] | ((unsigned char)buffer[1] << 8);
    else
        packetID = (unsigned char)buffer[0];

    // Header line
    ofs << "[" << getCurrentTime() << "] "
        << direction,
    // ByteArray line
    ofs << " raw bytes:  ";
    for (int i = 0; i < len; i++) {
        ofs << "0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
            << (unsigned int)(unsigned char)buffer[i];
        if (i < len - 1) ofs << ", ";
    }
    ofs << " \n";

    ofs << SEPARATOR;
    ofs.close();
}
// ─────────────────────────────────────────────

// ═════════════════════════════════════════════════════════════════════════════
// SEED Capture — hook "push eax" ที่ offset 0xD703 จาก base ของ map_cache.grf
//
//  x64dbg script เดิม:
//    6508D703 | 50 | push eax | logif(1, SEED: {mem;20@eax})
//
//  วิธี:
//    1. GetModuleHandleA("map_cache.grf") → หา base จริง (รองรับ ASLR)
//    2. TargetAddr = base + SEED_INSTRUCTION_OFFSET
//    3. Detours hook ด้วย __declspec(naked) → ก่อน "push eax" จริงทำงาน
//       ให้อ่าน eax → memcpy 20 bytes → log "[SEED] XX XX ..."
//    4. jmp → trampoline ของ Detours (ซึ่งมี "push eax" + jmp กลับ)
// ═════════════════════════════════════════════════════════════════════════════

// Offset ของ instruction "push eax" (6508D703) จาก base map_cache.grf (65080000)
// 0x6508D703 - 0x65080000 = 0xD703
static const ULONG_PTR SEED_INSTRUCTION_OFFSET = 0xD703;

// ─────────────────────────────────────────────
// Static Salt (Hardcoded Key) — scan หา pattern ใน MEM_IMAGE regions
//
//  ปัญหาเดิม: hardcode offset จาก map_cache.grf (65080000)
//    → 65378620 อยู่คนละ module → ได้ machine code มาแทน string
//
//  แก้: ไม่ต้องรู้ module base เลย — ใช้ VirtualQuery scan หา
//    ASCII pattern "gGaKzO7q8fLy1ipO1ykIvU1jU983Blzh" (32 bytes)
//    ใน memory regions ที่เป็น MEM_IMAGE + readable โดยตรง
//    → รองรับ ASLR ทุกกรณี ไม่ขึ้นกับ module ใดๆ
// ─────────────────────────────────────────────
static const char   SALT_PATTERN[] = "gGaKzO7q8fLy1ipO1ykIvU1jU983Blzh";
static const int    SALT_LEN       = 32; // sizeof(SALT_PATTERN) - 1

static void LogStaticSalt()
{
    const BYTE* found = nullptr;

    // วน scan ทุก memory region ในกระบวนการ
    MEMORY_BASIC_INFORMATION mbi = {};
    const BYTE* scanPtr = reinterpret_cast<const BYTE*>(0x10000); // ข้าม null page

    while (VirtualQuery(scanPtr, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        // เฉพาะ: committed + image (.rdata/.data) + readable (ไม่ใช่ guard/no-access)
        bool isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                                          PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                          && !(mbi.Protect & PAGE_GUARD);

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE && isReadable)
        {
            const BYTE* region = reinterpret_cast<const BYTE*>(mbi.BaseAddress);
            SIZE_T      size   = mbi.RegionSize;

            for (SIZE_T i = 0; i + SALT_LEN <= size; i++)
            {
                __try {
                    if (memcmp(region + i, SALT_PATTERN, SALT_LEN) == 0) {
                        found = region + i;
                        break;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            }
        }

        if (found) break;

        // เลื่อน pointer ไปจุดถัดไป พร้อม overflow guard
        const BYTE* next = reinterpret_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= scanPtr) break;
        scanPtr = next;
    }

    if (!found) {
        debug("LogStaticSalt: pattern not found in memory");
        return;
    }

    // ─── log ───
    char dbgMsg[64];
    snprintf(dbgMsg, sizeof(dbgMsg), "LogStaticSalt: found at 0x%08X", (DWORD)found);
    debug(dbgMsg);

    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream ofs(LOG_FILE, std::ios::app);
    if (!ofs.is_open()) return;

    // บรรทัด 1: address ที่พบจริง (ยืนยัน ASLR shift)
    ofs << "[" << getCurrentTime() << "] [SALT] Addr: 0x"
        << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
        << static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(found)) << "\n";

    // บรรทัด 2: Hex — แสดงแยก 16+16 เหมือน x64dbg
    ofs << "[" << getCurrentTime() << "] [SALT] Hex:";
    for (int i = 0; i < 16; i++)
        ofs << " " << std::uppercase << std::hex
            << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(found[i]);
    ofs << " |";
    for (int i = 16; i < 32; i++)
        ofs << " " << std::uppercase << std::hex
            << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(found[i]);
    ofs << "\n";

    // บรรทัด 3: ASCII (ควรเห็น gGaKzO7q8fLy1ipO1ykIvU1jU983Blzh)
    ofs << "[" << getCurrentTime() << "] [SALT] ASCII: ";
    for (int i = 0; i < 32; i++)
        ofs << static_cast<char>(found[i]);
    ofs << "\n" << SEPARATOR;

    ofs.close();
    debug("LogStaticSalt: salt logged OK");
}
// ─────────────────────────────────────────────

// Detours จะแก้ pointer นี้ให้ชี้ไป trampoline หลัง DetourAttach
typedef void(__cdecl* PFN_SeedPoint)();
static PFN_SeedPoint OriginalSeedPoint = nullptr;

// เรียกจาก SeedHook (naked) — รับ eax เป็น argument
static void LogSeedFromEax(DWORD eaxVal)
{
    BYTE seed[20] = {};

    // อ่าน 20 bytes ที่ [eax] อย่างปลอดภัย
    __try {
        memcpy(seed, reinterpret_cast<const void*>(eaxVal), 20);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // pointer ไม่ valid → ปล่อยผ่าน (seed จะเป็น 00 ทั้งหมด)
    }

    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream ofs(LOG_FILE, std::ios::app);
    if (!ofs.is_open()) return;

    // Format: [HH:MM:SS] [SEED] XX XX XX XX ... (20 bytes)
    ofs << "[" << getCurrentTime() << "] [SEED]";
    for (int i = 0; i < 20; i++) {
        ofs << " " << std::uppercase << std::hex
            << std::setw(2) << std::setfill('0')
            << static_cast<unsigned int>(seed[i]);
    }
    ofs << "\n" << SEPARATOR;
    ofs.close();
}

// naked hook — Detours จะ JMP มาที่นี่แทน "push eax" ตัวจริง
//
// ปัญหาเดิม: call LogSeedFromEax ทำลาย EFLAGS (ZF/CF/SF/OF ฯลฯ)
//   → ถ้าโค้ดเกมหลัง "push eax" มี Jcc ที่อ้างอิง flags → crash
//
// แก้ด้วย pushfd/popfd + pushad/popad เพื่อ snapshot state ทั้งหมด:
//
//   stack layout หลัง pushfd + pushad:
//     [esp+00] = EDI   ← pushad เรียงจากบน
//     [esp+04] = ESI
//     [esp+08] = EBP
//     [esp+12] = ESP (original, ไม่ใช้)
//     [esp+16] = EBX
//     [esp+20] = EDX
//     [esp+24] = ECX
//     [esp+28] = EAX   ← ค่าที่เราต้องการ
//     [esp+32] = EFLAGS (จาก pushfd)
__declspec(naked) static void SeedHook()
{
    __asm {
        pushfd                          // บันทึก EFLAGS ก่อนทุกอย่าง
        pushad                          // บันทึก EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI

        mov  eax, [esp + 28]           // ดึง EAX ดั้งเดิม (ก่อน pushad ไปแตะ)
        push eax                        // argument → LogSeedFromEax(DWORD eaxVal)
        call LogSeedFromEax             // log SEED — อาจแตะ EAX/ECX/EDX/flags ได้เต็มที่
        add  esp, 4                     // clean up argument (__cdecl)

        popad                           // คืน EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI ทั้งหมด
        popfd                           // คืน EFLAGS — โค้ดเกมเห็น flags เหมือนก่อน hook
        jmp  dword ptr [OriginalSeedPoint]  // → Detours trampoline → original code
    }
}

// ติดตั้ง SEED hook (เรียกจาก init หลัง HookWs2Functions)
static void InstallSeedHook()
{
    HMODULE hMod = GetModuleHandleA("map_cache.grf");
    if (!hMod) {
        debug("InstallSeedHook: map_cache.grf not found — SEED hook skipped");
        return;
    }

    // คำนวณ address จริงของ "push eax" โดยอ้างอิง base ที่ได้จริง
    ULONG_PTR targetAddr = reinterpret_cast<ULONG_PTR>(hMod) + SEED_INSTRUCTION_OFFSET;
    OriginalSeedPoint = reinterpret_cast<PFN_SeedPoint>(targetAddr);

    char dbgMsg[64];
    snprintf(dbgMsg, sizeof(dbgMsg), "InstallSeedHook: target = 0x%08X", (DWORD)targetAddr);
    debug(dbgMsg);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalSeedPoint, reinterpret_cast<PVOID>(SeedHook));
    LONG err = DetourTransactionCommit();

    if (err != NO_ERROR) {
        debug("InstallSeedHook: DetourTransactionCommit FAILED");
        OriginalSeedPoint = nullptr;
    }
    else {
        debug("InstallSeedHook: SEED hook installed OK");
    }
}

// ถอด SEED hook (เรียกจาก finish ก่อน UnhookWs2Functions)
static void UninstallSeedHook()
{
    if (!OriginalSeedPoint) return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OriginalSeedPoint, reinterpret_cast<PVOID>(SeedHook));
    DetourTransactionCommit();
    OriginalSeedPoint = nullptr;
    debug("UninstallSeedHook: SEED hook removed");
}
// ═════════════════════════════════════════════════════════════════════════════

void init();
void finish();
void HookWs2Functions();
void UnhookWs2Functions();
void sendDataToKore(char* buffer, int len, e_PacketType type);

extern "C" {
    int (WINAPI* OriginalRecv) (SOCKET s, char* buf, int len, int flags) = recv;
    int (WINAPI* OriginalRecvFrom) (SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = recvfrom;
    int (WINAPI* OriginalSend) (SOCKET s, const char* buf, int len, int flags) = send;
    int (WINAPI* OriginalSendTo) (SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) = sendto;
    int (WINAPI* OriginalConnect) (SOCKET s, const struct sockaddr* name, int namelen) = connect;
    int (WINAPI* OriginalSelect) (int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) = select;
    int (WINAPI* OriginalWSARecv) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecv;
    int (WINAPI* OriginalWSARecvFrom) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSARecvFrom;
    int (WINAPI* OriginalWSASend) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASend;
    int (WINAPI* OriginalWSASendTo) (SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) = WSASendTo;
    int (WINAPI* OriginalWSAAsyncSelect) (SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent) = WSAAsyncSelect;
}

// ─────────────────────────────────────────────
// sendDataToKore
//
// [แก้ไข ข้อ 2]
//   - RECEIVED (S->C) : บันทึก xkoreSendBuf เสมอ ไม่ว่า XKore จะ alive หรือไม่
//     เพื่อให้ OpenKore ได้รับข้อมูลทุก packet ที่ server ส่งมา
//   - SENDED   (C->S) : ส่งเฉพาะตอน XKore alive (พฤติกรรมเดิม)
// ─────────────────────────────────────────────
void sendDataToKore(char* buffer, int len, e_PacketType type)
{
    char* newbuf = (char*)malloc(len + 3);
    if (!newbuf) return;

    unsigned short sLen = (unsigned short)len;

    if (type == e_PacketType::RECEIVED) {
        // [ข้อ 2] ส่งข้อมูล S->C ไปหา XKore เสมอ
        memcpy(newbuf, "R", 1);
        memcpy(newbuf + 1, &sLen, 2);
        memcpy(newbuf + 3, buffer, len);
        xkoreSendBuf.append(newbuf, len + 3);
    }
    else {
        // SENDED: ส่งเฉพาะตอน XKore alive (C->S ควรผ่าน XKore เท่านั้น)
        bool isAlive = koreClientIsAlive;
        if (isAlive) {
            memcpy(newbuf, "S", 1);
            memcpy(newbuf + 1, &sLen, 2);
            memcpy(newbuf + 3, buffer, len);
            xkoreSendBuf.append(newbuf, len + 3);
        }
    }

    free(newbuf);
}

int WINAPI MyConnect(SOCKET s, const struct sockaddr *name, int namelen) {
    // ไม่ต้อง redirect อะไรทั้งนั้น — Client เชื่อมตรง Real Server
    return OriginalConnect(s, name, namelen);
}

int WINAPI HookedRecv(SOCKET socket, char* buffer, int len, int flags) {
    int ret_len = OriginalRecv(socket, buffer, len, flags);

    if (ret_len > 0) {
        logPacket(buffer, ret_len, "[S->C]");

        bool isHttp = (ret_len >= 4 && memcmp(buffer, "HTTP", 4) == 0);
        if (!isHttp) {
            roGameSocket = socket;
            sendDataToKore(buffer, ret_len, e_PacketType::RECEIVED);
        } else {
            roHttpSocket = socket;
        }
    }

    return ret_len;  // คืนข้อมูลเดิม — Client ได้รับจาก Real Server ปกติ
}

// int (WINAPI* OriginalRecvFrom)
int WINAPI HookedRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    return  OriginalRecvFrom(s, buf, len, flags, from, fromlen);
}

// HookedSend — ส่งไปทั้งสองที่
int WINAPI HookedSend(SOCKET s, const char* buffer, int len, int flags) {
    if (len <= 0) return 0;

    bool isHttp = (len >= 4 && (
        memcmp(buffer, "POST", 4) == 0 ||
        memcmp(buffer, "GET ", 4) == 0 ||
        memcmp(buffer, "--",   2) == 0
    ));

    logPacket(buffer, len, "[C->S]");

    if (isHttp) {
        roHttpSocket = s;
        return OriginalSend(s, buffer, len, flags);
    }

    roGameSocket = s;

    // Phase 1-3: ส่งข้อมูล Client ไปยัง Real Server ตามปกติ
    int ret = OriginalSend(s, buffer, len, flags);

    // พร้อมกันนั้น ส่งสำเนาให้ OpenKore สำหรับสังเกตการณ์
    sendDataToKore((char*)buffer, len, e_PacketType::SENDED);

    return ret;  // คืนค่าจริงให้ Client
}

// int (WINAPI* OriginalSendTo)
int WINAPI HookedSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    return OriginalSendTo(s, buf, len, flags, to, tolen);
}

// int (WINAPI* OriginalConnect)
int WINAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    return OriginalConnect(s, name, namelen);
}

// int (WINAPI* OriginalSelect)
int WINAPI HookedSelect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) {
    return OriginalSelect(nfds, readfds, writefds, exceptfds, timeout);
}

// int (WINAPI* OriginalWSARecv)
int WINAPI HookedWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSARecvFrom)
int WINAPI HookedWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSASend)
int WINAPI HookedWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSASendTo)
int WINAPI HookedWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    return OriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSAAsyncSelect)
int WINAPI HookedWSAAsyncSelect(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent) {
    return OriginalWSAAsyncSelect(s, hWnd, wMsg, lEvent);
}

// Process a packet that the X-Kore server sent us
static void processPacket(Packet* packet)
{
    switch (packet->ID) {
    case 'S':
        // บอทสั่งส่งไป RO Server → ใช้ roGameSocket เสมอ
        if (roGameSocket != INVALID_SOCKET && isConnected(roGameSocket))
            OriginalSend(roGameSocket, packet->data, packet->len, 0);
        break;

    case 'R':
        roSendBuf.append(packet->data, packet->len);
        break;

    case 'K': default:
        break;
    }
}

void koreConnectionMain()
{
    char buf[BUF_SIZE + 1];
    char pingPacket[3];
    unsigned short pingPacketLength = 0;
    DWORD koreClientTimeout, koreClientPingTimeout, reconnectTimeout;
    string koreClientRecvBuf;

    debug("Thread started...");
    koreClientTimeout = GetTickCount();
    koreClientPingTimeout = GetTickCount();
    reconnectTimeout = 0;

    memcpy(pingPacket, "K", 1);
    memcpy(pingPacket + 1, &pingPacketLength, 2);

    while (keepMainThread) {
        bool isAlive = koreClientIsAlive;
        bool isAliveChanged = false;

        koreClientIsAlive = koreClient != INVALID_SOCKET;

        if ((!isAlive || !isConnected(koreClient) || GetTickCount() - koreClientTimeout > TIMEOUT)
            && GetTickCount() - reconnectTimeout > RECONNECT_INTERVAL) {
            debug("Connecting to X-Kore server...");

            if (koreClient != INVALID_SOCKET)
                closesocket(koreClient);
            koreClient = createSocket(XKORE_SERVER_PORT);

            isAlive = koreClient != INVALID_SOCKET;
            isAliveChanged = true;
            if (!isAlive)
                debug("Failed...");
            else
                koreClientTimeout = GetTickCount();
            reconnectTimeout = GetTickCount();
        }

        // Receive data from the X-Kore server
        if (isAlive) {
            if (!imalive) {
                debug("Connected to xKore-Server");
                imalive = true;
            }
            int ret;

            ret = readSocket(koreClient, buf, BUF_SIZE);
            if (ret == SF_CLOSED) {
                debug("X-Kore server exited");
                closesocket(koreClient);
                koreClient = INVALID_SOCKET;
                isAlive = false;
                isAliveChanged = true;
                imalive = false;
            }
            else if (ret > 0) {
                Packet* packet;
                int next = 0;
                debug("Received Packet from OpenKore...");
                koreClientRecvBuf.append(buf, ret);
                while ((packet = unpackPacket(koreClientRecvBuf.c_str(), koreClientRecvBuf.size(), next))) {
                    processPacket(packet);
                    free(packet);
                    koreClientRecvBuf.erase(0, next);
                }
                koreClientTimeout = GetTickCount();
            }
        }

        // Check whether we have data to send to the X-Kore server
        if (xkoreSendBuf.size()) {
            if (isAlive) {
                OriginalSend(koreClient, (char*)xkoreSendBuf.c_str(), xkoreSendBuf.size(), 0);
            }
            else {
                Packet* packet;
                int next;

                // [ข้อ 2] ถ้า XKore ไม่ alive:
                //   - 'S' (C->S) : ส่งต่อไปยัง RO server โดยตรง
                //   - 'R' (S->C) : drop ไป เพราะ client รับไปแล้ว
                while ((packet = unpackPacket(xkoreSendBuf.c_str(), xkoreSendBuf.size(), next))) {
                    if (packet->ID == 'S')
                        OriginalSend(roGameSocket, (char*)packet->data, packet->len, 0); // FIX-B: roServer was INVALID_SOCKET
                    free(packet);
                    xkoreSendBuf.erase(0, next);
                }
            }
            xkoreSendBuf.erase();
        }

        // Ping the X-Kore server to keep the connection alive
        if (koreClientIsAlive && GetTickCount() - koreClientPingTimeout > PING_INTERVAL) {
            OriginalSend(koreClient, pingPacket, 3, 0);
            koreClientPingTimeout = GetTickCount();
        }

        if (isAliveChanged) {
            koreClientIsAlive = isAlive;
        }
        Sleep(SLEEP_TIME);
    }
}

/* Init Function. Here we call the necessary functions */
void init()
{
    debugInit();
    debug("Hooking WS2_32 Functions...");
    HookWs2Functions();
    debug("WS2_32 Functions Hooked...");

    // ติดตั้ง SEED hook (รองรับ ASLR — หา base จาก GetModuleHandleA)
    InstallSeedHook();

    // อ่าน Static Salt จาก .rdata ครั้งเดียว (ไม่ต้อง hook — เป็นข้อมูลคงที่)
    LogStaticSalt();

    debug("Creating Main thread...");
    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)koreConnectionMain, 0, 0, NULL);
    if (hThread) {
        debug("Main Thread created...");
    }
    else {
        debug("Failed to Create Thread...");
        finish();
    }
}

/* Hook the WS2_32.dll functions */
void HookWs2Functions()
{
    DisableThreadLibraryCalls(hModule);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)OriginalRecv, HookedRecv);
    DetourAttach(&(PVOID&)OriginalRecvFrom, HookedRecvFrom);
    DetourAttach(&(PVOID&)OriginalSend, HookedSend);
    DetourAttach(&(PVOID&)OriginalSendTo, HookedSendTo);
    // DetourAttach(&(PVOID&)OriginalConnect, MyConnect);
    DetourAttach(&(PVOID&)OriginalSelect, HookedSelect);
    DetourAttach(&(PVOID&)OriginalWSARecv, HookedWSARecv);
    DetourAttach(&(PVOID&)OriginalWSARecvFrom, HookedWSARecvFrom);
    DetourAttach(&(PVOID&)OriginalWSASend, HookedWSASend);
    DetourAttach(&(PVOID&)OriginalWSASendTo, HookedWSASendTo);
    DetourAttach(&(PVOID&)OriginalWSAAsyncSelect, HookedWSAAsyncSelect);

    DetourTransactionCommit();
}

void finish()
{
    // ถอด SEED hook ก่อนเสมอ
    UninstallSeedHook();

    debug("Unhooking WS2_32 Functions...");
    UnhookWs2Functions();
    debug("WS2_32 Functions Unhooked...");
    debug("Closing Main thread...");
    if (hThread) {
        keepMainThread = false;
        debug("Signal to Close Main Thread Sended...");
    }
    else {
        debug("Main Thread was not created...");
    }
}

/* Unhook the WS2_32.dll functions */
void UnhookWs2Functions()
{
    DisableThreadLibraryCalls(hModule);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)OriginalRecv, HookedRecv);
    DetourDetach(&(PVOID&)OriginalRecvFrom, HookedRecvFrom);
    DetourDetach(&(PVOID&)OriginalSend, HookedSend);
    DetourDetach(&(PVOID&)OriginalSendTo, HookedSendTo);
    // DetourDetach(&(PVOID&)OriginalConnect, MyConnect);
    DetourDetach(&(PVOID&)OriginalSelect, HookedSelect);
    DetourDetach(&(PVOID&)OriginalWSARecv, HookedWSARecv);
    DetourDetach(&(PVOID&)OriginalWSARecvFrom, HookedWSARecvFrom);
    DetourDetach(&(PVOID&)OriginalWSASend, HookedWSASend);
    DetourDetach(&(PVOID&)OriginalWSASendTo, HookedWSASendTo);
    DetourDetach(&(PVOID&)OriginalWSAAsyncSelect, HookedWSAAsyncSelect);

    DetourTransactionCommit();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        init();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}