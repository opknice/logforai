// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include "pch.h"
#include "NetRedirect.h"
#include "Common.h"

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
    // Is Kore running?
    bool isAlive = koreClientIsAlive;

    if (isAlive)
    {
        char* newbuf = (char*)malloc(len + 3);
        unsigned short sLen = (unsigned short)len;
        if (type == e_PacketType::RECEIVED) {
            memcpy(newbuf, "R", 1);
        }
        else {
            memcpy(newbuf, "S", 1);
        }
        memcpy(newbuf + 1, &sLen, 2);
        memcpy(newbuf + 3, buffer, len);
        xkoreSendBuf.append(newbuf, len + 3);
        free(newbuf);
    }
}

//  int (WINAPI* OriginalRecv)
int WINAPI HookedRecv(SOCKET socket, char* buffer, int len, int flags) {
    debug("Called MyRecv ...");
    int ret_len = OriginalRecv(socket, buffer, len, flags);

    if (ret_len != SOCKET_ERROR && ret_len > 0) {
        roServer = socket;
        sendDataToKore(buffer, ret_len, e_PacketType::RECEIVED);
    }

    return ret_len;

}

// int (WINAPI* OriginalRecvFrom)
int WINAPI HookedRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    return  OriginalRecvFrom(s, buf, len, flags, from, fromlen);
}

// int (WINAPI* OriginalSend)
int WINAPI HookedSend(SOCKET s, const char* buffer, int len, int flags) {
    debug("Called MySend ...");
    int ret;

    // See if the socket to the RO server is still alive, and make
    // sure WSAGetLastError() returns the right error if something's wrong
    ret = OriginalSend(s, buffer, 0, flags);

    if (ret != SOCKET_ERROR && len > 0) {
        bool isAlive = koreClientIsAlive;
        if (isAlive) {
            roServer = s;
            sendDataToKore((char*)buffer, len, e_PacketType::SENDED);
            return len;

        }
        else {
            // Send packet directly to the RO server
            ret = OriginalSend(s, buffer, len, flags);
            return ret;
        }
    }
    else
        return ret;
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
static void
processPacket(Packet* packet)
{
    switch (packet->ID) {
    case 'S': // Send a packet to the RO server
        debug("Sending Data From Openkore to Server...");
        if (roServer != INVALID_SOCKET && isConnected(roServer))
            OriginalSend(roServer, packet->data, packet->len, 0);
        break;

    case 'R': // Fool the RO client into thinking that we got a packet from the RO server
        // We copy the data in this packet into a string
        // Next time the RO client calls recv(), this packet will be returned, along with
        // whatever data the RO server sent
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

