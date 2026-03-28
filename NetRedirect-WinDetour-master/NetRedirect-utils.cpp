#include "pch.h"
#include <stdlib.h>
#include <stdarg.h>
#include "NetRedirect.h"
#include "Common.h"


/* Creates a packet data structure.
 * Returns NULL if data is not a full packet, or a Packet structure.
 * next is the offset of the next packet, in case data contains more than one packet.
 */
Packet*
unpackPacket(const char* data, int len, int& next)
{
	Packet* packet;

	if (len < 3)
		return NULL;

	packet = (Packet*)calloc(sizeof(Packet), 1);
	packet->ID = (unsigned char)data[0];
	memcpy(&(packet->len), data + 1, 2);
	if (len < packet->len) {
		free(packet);
		return NULL;
	}

	if (packet->len > 0)
		packet->data = (char*)data + 3;
	next = packet->len + 3;
	return packet;
}

SOCKET
createSocket(int port)
{
	sockaddr_in addr;
	SOCKET sock;
	DWORD arg = 1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
		return INVALID_SOCKET;
	// Set to non-blocking mode
	ioctlsocket(sock, FIONBIO, &arg);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	while (OriginalConnect(sock, (struct sockaddr*) & addr, sizeof(sockaddr_in)) == SOCKET_ERROR) {
		if (WSAGetLastError() == WSAEISCONN)
			break;
		else if (WSAGetLastError() != WSAEWOULDBLOCK) {
			closesocket(sock);
			return INVALID_SOCKET;
		}
		else
			Sleep(10);
	}

	return sock;
}

// Checks whether a socket is still connected
bool
isConnected(SOCKET s)
{
	fd_set fds;
	long count;
	timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 1;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	count = OriginalSelect(1, NULL, &fds, NULL, &tv);
	return (bool)count;
}

// Checks whether there's data available from a socket
bool
dataWaiting(SOCKET s)
{
	fd_set fds;
	long count;
	timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = 1;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	count = OriginalSelect(1, &fds, NULL, NULL, &tv);
	return (bool)count;
}

// ตรวจว่า buffer นี้เป็น HTTP traffic หรือเปล่า
// โดยดูจาก magic bytes ที่ขึ้นต้น
bool isHttpTraffic(const char* buffer, int len) {
    if (len < 2) return false;

    // HTTP Request: "POST ", "GET ", "PUT " ฯลฯ
    if (len >= 4 && memcmp(buffer, "POST", 4) == 0) return true;
    if (len >= 3 && memcmp(buffer, "GET", 3) == 0) return true;

    // HTTP Response: "HTTP/1.1 ..."
    if (len >= 5 && memcmp(buffer, "HTTP/", 5) == 0) return true;

    // multipart boundary: "--" ที่ใช้ใน form-data
    // ต้องระวังเพราะ "--" อาจเป็น RO packet ได้ด้วย
    // จึงตรวจยาวขึ้นอีก 24 chars ซึ่งเป็น MIME boundary
    if (len >= 26 && memcmp(buffer, "--------------------------", 26) == 0) return true;

    // JSON fragment ที่เป็น continuation ของ HTTP response
    // ขึ้นต้นด้วย ":31," หรือ JSON object/array
    if (len >= 2 && buffer[0] == ':' && (buffer[1] >= '0' && buffer[1] <= '9')) return true;

    return false;
}

int
readSocket(SOCKET s, char* buf, int len)
{
	int ret = OriginalRecv(s, buf, len, 0);

	if (ret == 0)
		return SF_CLOSED;
	else if (ret > 0)
		return ret;
	else if (ret == SOCKET_ERROR) {
		if (WSAGetLastError() == WSAEWOULDBLOCK)
			return SF_NODATA;
		else
			return SF_CLOSED;
	}
	else
		return SF_CLOSED;
}

/* Alloc Console to Show DEBUG messages */
void debugInit()
{
	if (DEBUG)
	{
		if (!AllocConsole())
		{
			MessageBox(NULL, L"Error - Failed to Alloc Console", NULL, MB_ICONEXCLAMATION);
			exit(0);
		}
		else
		{
			FILE* fp;
			freopen_s(&fp, "CONOUT$", "w", stdout);

			debug("------------------- DEBUG MODE -------------------\n");
		}
	}
}

/* Print DEBUG messages in Console */
void debug(const char* message)
{
	if (DEBUG)
	{
		std::cout << message << std::endl;
	}
}
