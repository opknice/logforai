// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include "pch.h"
#include "NetRedirect.h"
#include "Common.h"
#include <unordered_set>

// load Microsoft Detour Lib
#include "detours.h"
#pragma comment(lib, "detours.lib")

HMODULE hModule;
HANDLE hThread;
bool keepMainThread = true;

// Connection to the X-Kore server that Kore created
static SOCKET koreClient = INVALID_SOCKET;
static bool koreClientIsAlive = false;
static SOCKET roServer = INVALID_SOCKET;
static string roSendBuf("");	// Data to send to the RO client
static string xkoreSendBuf("");	// Data to send to the X-Kore server
bool imalive = false;
static std::unordered_set<SOCKET> mapServerSockets;
static CRITICAL_SECTION socketSetLock;
static FILE* logFile = nullptr;
static CRITICAL_SECTION logFileLock;
static bool logFileReady = false;

// Helper: ตรวจว่า socket นี้เป็น Map Server socket หรือเปล่า
static inline bool isMapSocket(SOCKET s) {
    EnterCriticalSection(&socketSetLock);
    bool found = (mapServerSockets.find(s) != mapServerSockets.end());
    LeaveCriticalSection(&socketSetLock);
    return found;
}

static inline void registerMapSocket(SOCKET s) {
    EnterCriticalSection(&socketSetLock);
    mapServerSockets.insert(s);
    LeaveCriticalSection(&socketSetLock);
    debug("Map socket registered");
}

static inline void unregisterMapSocket(SOCKET s) {
    EnterCriticalSection(&socketSetLock);
    mapServerSockets.erase(s);
    LeaveCriticalSection(&socketSetLock);
}

static std::string buildWSABuffer(const WSABUF* lpBuffers, DWORD dwBufferCount, DWORD bytesToCopy = 0) {
    DWORD total = bytesToCopy;
    if (total == 0) {
        for (DWORD i = 0; i < dwBufferCount; ++i) {
            total += lpBuffers[i].len;
        }
    }

    std::string data;
    data.reserve(total);
    DWORD remaining = total;

    for (DWORD i = 0; i < dwBufferCount && remaining > 0; ++i) {
        DWORD len = lpBuffers[i].len;
        if (len == 0 || lpBuffers[i].buf == nullptr)
            continue;
        DWORD take = len;
        if (take > remaining)
            take = remaining;
        data.append(lpBuffers[i].buf, take);
        remaining -= take;
    }

    return data;
}

static std::string bytesToHex(const char* buffer, int len) {
    std::string hex;
    hex.reserve(len * 3);
    const unsigned char* data = reinterpret_cast<const unsigned char*>(buffer);
    static const char* digits = "0123456789ABCDEF";

    for (int i = 0; i < len; ++i) {
        unsigned char c = data[i];
        hex.push_back(digits[c >> 4]);
        hex.push_back(digits[c & 0x0F]);
        if (i + 1 < len)
            hex.push_back(' ');
    }
    return hex;
}

static void logMessage(const char* format, ...) {
    if (!logFileReady)
        return;

    EnterCriticalSection(&logFileLock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(logFile, "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, format);
    vfprintf(logFile, format, args);
    va_end(args);
    fprintf(logFile, "\n");
    fflush(logFile);

    LeaveCriticalSection(&logFileLock);
}

static void logPacket(const char* direction, const char* source, const char* buffer, int len) {
    if (!logFileReady || len <= 0)
        return;

    std::string hex = bytesToHex(buffer, len);
    logMessage("[%s] %s [%d bytes]: %s", direction, source, len, hex.c_str());
}

static void logInit() {
    InitializeCriticalSection(&logFileLock);

    char modulePath[MAX_PATH] = {0};
    std::string path = "NetRedirect.log";
    if (::hModule && GetModuleFileNameA(::hModule, modulePath, MAX_PATH) != 0) {
        path = modulePath;
        size_t pos = path.find_last_of("\\/");
        if (pos != std::string::npos)
            path = path.substr(0, pos + 1);
        path += "NetRedirect.log";
    }

    logFile = fopen(path.c_str(), "a");
    if (logFile) {
        logFileReady = true;
        logMessage("=== NetRedirect log started ===");
    }
}

static void logClose() {
    if (!logFileReady)
        return;

    logMessage("=== NetRedirect log ended ===");
    fclose(logFile);
    logFile = nullptr;
    logFileReady = false;
    DeleteCriticalSection(&logFileLock);
}

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

void sendDataToKore(char* buffer, int len, e_PacketType type) {
    bool isAlive = koreClientIsAlive;

    if (!isAlive) return;

    // ── HTTP Filter ──────────────────────────────────────────────────────────
    // กรอง HTTP traffic ออกก่อนส่งไป OpenKore
    // เหตุผล: client นี้ใช้ socket เดิมส่ง HTTP request ไปยัง config server
    //         OpenKore ไม่รู้จัก HTTP bytes และจะ parse ผิดพลาด
    if (isHttpTraffic(buffer, len)) {
        debug("sendDataToKore: HTTP traffic detected and filtered out");
        logMessage("HTTP_FILTER sendDataToKore [%d bytes]", len);
        return; // ทิ้งทิ้ง → rag.exe ได้รับ HTTP response ตามปกติอยู่แล้ว
                // เพราะเราแค่ไม่ forward ไปให้ OpenKore เท่านั้น
    }

    logPacket("SERVER->OPENKORE", "sendDataToKore", buffer, len);

    // ── Normal RO Packet ─────────────────────────────────────────────────────
    char* newbuf = (char*)malloc(len + 3);
    if (!newbuf) return; // guard allocation failure

    unsigned short sLen = (unsigned short)len;
    memcpy(newbuf, (type == e_PacketType::RECEIVED) ? "R" : "S", 1);
    memcpy(newbuf + 1, &sLen, 2);
    memcpy(newbuf + 3, buffer, len);
    xkoreSendBuf.append(newbuf, len + 3);
    free(newbuf);
}

//  int (WINAPI* OriginalRecv)
int WINAPI HookedRecv(SOCKET socket, char* buffer, int len, int flags) {
    debug("Called HookedRecv...");
    int ret_len = OriginalRecv(socket, buffer, len, flags);

    if (ret_len != SOCKET_ERROR && ret_len > 0) {
        if (isMapSocket(socket)) {
            roServer = socket;
            logPacket("SERVER->OPENKORE", "HookedRecv", buffer, ret_len);
            sendDataToKore(buffer, ret_len, e_PacketType::RECEIVED);
        } else {
            logPacket("SERVER->CLIENT", "HookedRecv", buffer, ret_len);
        }
    }

    return ret_len;
}

// int (WINAPI* OriginalRecvFrom)
int WINAPI HookedRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    int ret = OriginalRecvFrom(s, buf, len, flags, from, fromlen);
    if (ret > 0) {
        if (isMapSocket(s)) {
            roServer = s;
            logPacket("SERVER->OPENKORE", "HookedRecvFrom", buf, ret);
            sendDataToKore(buf, ret, e_PacketType::RECEIVED);
        } else {
            logPacket("SERVER->CLIENT", "HookedRecvFrom", buf, ret);
        }
    }
    return ret;
}

// int (WINAPI* OriginalSend)
int WINAPI HookedSend(SOCKET s, const char* buffer, int len, int flags) {
    debug("Called HookedSend...");

    // ถ้าไม่ใช่ Map Server socket → ส่งตรงไปเลย ไม่ผ่าน OpenKore
    if (!isMapSocket(s)) {
        return OriginalSend(s, buffer, len, flags);
    }

    // จากนี้เป็น Map Server socket
    int ret = OriginalSend(s, buffer, 0, flags); // probe connection status

    if (ret != SOCKET_ERROR && len > 0) {
        bool isAlive = koreClientIsAlive;
        if (isAlive) {
            roServer = s;
            sendDataToKore((char*)buffer, len, e_PacketType::SENDED);
            return len;
        } else {
            ret = OriginalSend(s, buffer, len, flags);
            return ret;
        }
    }
    return ret;
}

// int (WINAPI* OriginalSendTo)
int WINAPI HookedSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    if (!isMapSocket(s)) {
        logPacket("CLIENT->SERVER", "HookedSendTo", buf, len);
        return OriginalSendTo(s, buf, len, flags, to, tolen);
    }

    logPacket("OPENKORE->SERVER", "HookedSendTo", buf, len);
    if (koreClientIsAlive) {
        roServer = s;
        sendDataToKore((char*)buf, len, e_PacketType::SENDED);
        return len;
    }

    return OriginalSendTo(s, buf, len, flags, to, tolen);
}

// int (WINAPI* OriginalConnect)
int WINAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    int ret = OriginalConnect(s, name, namelen);

    // ตรวจ port ปลายทาง — cast ได้เลยเพราะ RO ใช้ IPv4
    if (name != nullptr && name->sa_family == AF_INET) {
        const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(name);
        int port = ntohs(addr->sin_port);

        if (port == MAP_SERVER_PORT) {
            // socket นี้กำลัง connect ไปที่ Map Server → register ไว้
            registerMapSocket(s);
            debug("HookedConnect: Map Server socket detected on port 5121");
        }
    }

    return ret;
}

// int (WINAPI* OriginalSelect)
int WINAPI HookedSelect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout) {
    return OriginalSelect(nfds, readfds, writefds, exceptfds, timeout);
}

// int (WINAPI* OriginalWSARecv)
int WINAPI HookedWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int ret = OriginalWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

    if (!isMapSocket(s))
        return ret;

    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        roServer = s;
        std::string data = buildWSABuffer(lpBuffers, dwBufferCount, *lpNumberOfBytesRecvd);
        if (!data.empty()) {
            logPacket("SERVER->OPENKORE", "HookedWSARecv", data.data(), (int)data.size());
            if (koreClientIsAlive)
                sendDataToKore((char*)data.data(), (int)data.size(), e_PacketType::RECEIVED);
        }
    }

    return ret;
}

// int (WINAPI* OriginalWSARecvFrom)
int WINAPI HookedWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int ret = OriginalWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

    if (!isMapSocket(s))
        return ret;

    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        roServer = s;
        std::string data = buildWSABuffer(lpBuffers, dwBufferCount, *lpNumberOfBytesRecvd);
        if (!data.empty()) {
            logPacket("SERVER->OPENKORE", "HookedWSARecvFrom", data.data(), (int)data.size());
            if (koreClientIsAlive)
                sendDataToKore((char*)data.data(), (int)data.size(), e_PacketType::RECEIVED);
        }
    }

    return ret;
}

// int (WINAPI* OriginalWSASend)
int WINAPI HookedWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!isMapSocket(s))
        return OriginalWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

    DWORD totalBytes = 0;
    for (DWORD i = 0; i < dwBufferCount; ++i)
        totalBytes += lpBuffers[i].len;

    if (totalBytes == 0)
        return OriginalWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

    if (koreClientIsAlive) {
        std::string data = buildWSABuffer(lpBuffers, dwBufferCount, totalBytes);
        if (!data.empty()) {
            logPacket("OPENKORE->SERVER", "HookedWSASend", data.data(), (int)data.size());
            sendDataToKore((char*)data.data(), (int)data.size(), e_PacketType::SENDED);
        }
        if (lpNumberOfBytesSent)
            *lpNumberOfBytesSent = totalBytes;
        return 0;
    }

    return OriginalWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSASendTo)
int WINAPI HookedWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!isMapSocket(s))
        return OriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);

    DWORD totalBytes = 0;
    for (DWORD i = 0; i < dwBufferCount; ++i)
        totalBytes += lpBuffers[i].len;

    if (totalBytes == 0)
        return OriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);

    if (koreClientIsAlive) {
        std::string data = buildWSABuffer(lpBuffers, dwBufferCount, totalBytes);
        if (!data.empty()) {
            logPacket("OPENKORE->SERVER", "HookedWSASendTo", data.data(), (int)data.size());
            sendDataToKore((char*)data.data(), (int)data.size(), e_PacketType::SENDED);
        }
        if (lpNumberOfBytesSent)
            *lpNumberOfBytesSent = totalBytes;
        return 0;
    }

    return OriginalWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

// int (WINAPI* OriginalWSAAsyncSelect)
int WINAPI HookedWSAAsyncSelect(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent) {
    return OriginalWSAAsyncSelect(s, hWnd, wMsg, lEvent);
}

// Process a packet that the X-Kore server sent us
static void
processPacket(Packet* packet)
{
    switch (packet->ID) {
    case 'S': // Send a packet to the RO server
        logPacket("OPENKORE->SERVER", "processPacket", packet->data, packet->len);
        debug("Sending Data From Openkore to Server...");
        if (roServer != INVALID_SOCKET && isConnected(roServer))
            OriginalSend(roServer, packet->data, packet->len, 0);
        break;

    case 'R': // Fool the RO client into thinking that we got a packet from the RO server
        // We copy the data in this packet into a string
        // Next time the RO client calls recv(), this packet will be returned, along with
        // whatever data the RO server sent
        logPacket("OPENKORE->CLIENT", "processPacket", packet->data, packet->len);
        debug("Sending Data From Openkore to Client...");
        roSendBuf.append(packet->data, packet->len);
        break;

    case 'K': default: // Keep-alive
        debug("Received Keep-Alive Packet...");
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

        // Attempt to connect to the X-Kore server if necessary
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
                // Connection closed
                debug("X-Kore server exited");
                closesocket(koreClient);
                koreClient = INVALID_SOCKET;
                isAlive = false;
                isAliveChanged = true;
                imalive = false;

            }
            else if (ret > 0) {
                // Data available
                Packet* packet;
                int next = 0;
                debug("Received Packet from OpenKore...");
                koreClientRecvBuf.append(buf, ret);
                while ((packet = unpackPacket(koreClientRecvBuf.c_str(), koreClientRecvBuf.size(), next))) {
                    // Packet is complete
                    processPacket(packet);
                    free(packet);
                    koreClientRecvBuf.erase(0, next);
                }

                // Update timeout
                koreClientTimeout = GetTickCount();
            }
        }


        // Check whether we have data to send to the X-Kore server
        // This data originates from the RO client and is supposed to go to the real RO server
        if (xkoreSendBuf.size()) {
            if (isAlive) {
                OriginalSend(koreClient, (char*)xkoreSendBuf.c_str(), xkoreSendBuf.size(), 0);

            }
            else {
                Packet* packet;
                int next;

                // Kore is not running; send it to the RO server instead,
                // if this packet is supposed to go to the RO server ('S')
                // Ignore packets that are meant for Kore ('R')
                while ((packet = unpackPacket(xkoreSendBuf.c_str(), xkoreSendBuf.size(), next))) {
                    if (packet->ID == 'S')
                        OriginalSend(roServer, (char*)packet->data, packet->len, 0);
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
    InitializeCriticalSection(&socketSetLock); // ← เพิ่มตรงนี้
    logInit();
    debugInit();
    debug("Hooking WS2_32 Functions...");
    HookWs2Functions();
    debug("WS2_32 Functions Hooked...");
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
    // disable libary call
    DisableThreadLibraryCalls(hModule);

    // detour stuff
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //We attach our hooked function the the original 
    /* HOOK CUSTOM FUNCTION*/

    // WS2_32.dll functions 
    DetourAttach(&(PVOID&)OriginalRecv, HookedRecv);
    DetourAttach(&(PVOID&)OriginalRecvFrom, HookedRecvFrom);
    DetourAttach(&(PVOID&)OriginalSend, HookedSend);
    DetourAttach(&(PVOID&)OriginalSendTo, HookedSendTo);
    DetourAttach(&(PVOID&)OriginalConnect, HookedConnect);
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
    logClose();
}

/* Unhook the WS2_32.dll functions */
void UnhookWs2Functions()
{
    // disable libary call
    DisableThreadLibraryCalls(hModule);

    // detour stuff
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    //We attach our hooked function the the original 
    /* UNHOOK CUSTOM FUNCTION*/

    // WS2_32.dll functions 
    DetourDetach(&(PVOID&)OriginalRecv, HookedRecv);
    DetourDetach(&(PVOID&)OriginalRecvFrom, HookedRecvFrom);
    DetourDetach(&(PVOID&)OriginalSend, HookedSend);
    DetourDetach(&(PVOID&)OriginalSendTo, HookedSendTo);
    DetourDetach(&(PVOID&)OriginalConnect, HookedConnect);
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
    ::hModule = hModule;
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

