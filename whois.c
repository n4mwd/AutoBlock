/*
This source file is part of the AutoBlock project.

Copyright (C) 2026 Dennis Hawkins

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

If you use this code in any way, I would love to hear from you.  My email
address is: dennis@galliform.com
*/

// This module manages access to the whois server.

#include "AutoBlock.h"

#define RADB_HOST "whois.radb.net"
#define RADB_PORT 43



DWORD Domain2Ip(char *str)
{

    DWORD ip;


#if defined(__BORLANDC__)

    struct hostent *server;


    server = gethostbyname(str);

    if (server == NULL)
    {
        PrintErr(WARN, "Failed to resolve: %s\n", str);
        return 0;
    }
    memcpy(&ip, server->h_addr, server->h_length);
    ip = ntohl(ip);  // flip order
#else


    struct addrinfo hints;

    struct addrinfo *res;
    int status;

    // Configure lookup criteria for IPv4 TCP
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        // Force IPv4
    hints.ai_socktype = SOCK_STREAM;  // Stream socket (TCP)

    // Perform the DNS lookup
    status = getaddrinfo(str, NULL, &hints, &res);
    if (status != 0)
    {
        PrintErr(WARN, "Failed to resolve: %s (%s)\n", str, gai_strerror(status));
        return 0;
    }

    // Extract the network byte order address
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    ip = ipv4->sin_addr.s_addr;

    // Convert network byte order to host byte order
    ip = ntohl(ip);

    // Prevent memory leaks by freeing the allocated linked list
    freeaddrinfo(res);

#endif


    return(ip);

}




/* =========================================================================
   THE CROSS-COMPILER CONNECT FUNCTION
   ========================================================================= */
int connect_to_server(char *url, int port)
{
    /* ANSI C Strict: All local variables MUST be declared at the very top */
    SOCKET_TYPE sock_fd;

    #if defined(__BORLANDC__)
      struct hostent *server;
      struct sockaddr_in server_addr;
    #else
      struct addrinfo hints, *res;
      char portStr[16];
    #endif

if (!url || !url[0]) return(-1);



#if defined(__BORLANDC__)
    /* ---------------------------------------------------------------------
       PATH A: Borland C++ v5.02 Branch (Legacy Winsock gethostbyname)
       --------------------------------------------------------------------- */

    /* Resolve domain name */
    server = gethostbyname(url);
    if (server == NULL)
    {
        PrintErr(WARN, "Failed to resolve hostname: %s\n", url);
        return -1;
    }

    /* Configure target sockaddr_in layout safely */
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((WORD) port);
    memcpy((char *)&server_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);

    /* Create the network socket */
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == INVALID_SOCKET_VAL)
    {
        PrintErr(WARN, "Failed to create socket.\n");
        return -1;
    }

    SetNetTmo(sock_fd, 5);   // set 5 second timeout

    /* Connect to the server */
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        PrintErr(WARN, "Failed to connect to %s.\n", url);
        CLOSE_SOCKET(sock_fd);
        return -1;
    }

#else

    /* ---------------------------------------------------------------------
       PATH B: Linux GCC Branch (Modern Protocol-Independent getaddrinfo)
       --------------------------------------------------------------------- */

    sock_fd = INVALID_SOCKET_VAL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       /* IPv4 */
    hints.ai_socktype = SOCK_STREAM; /* TCP */

    /* Resolve domain name to IP address */
    sprintf(portStr, "%5d", port);
    if (getaddrinfo(url, portStr, &hints, &res) != 0)
    {
        PrintErr(WARN, "Failed to resolve hostname: %s\n", url);
        return -1;
    }

    /* Create the network socket */
    sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd < 0)
    {
        PrintErr(WARN, "Failed to create socket");
        freeaddrinfo(res);
        return -1;
    }

    SetNetTmo(sock_fd, 5);   // set 5 second timeout

    /* Connect to the server */
    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0)
    {
        PrintErr(WARN, "Failed to connect to %s.\n", url);
        CLOSE_SOCKET(sock_fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

#endif

    /* Return socket descriptor safely casted to int */
    return (int)sock_fd;
}




// Read up to BufSize bytes from network source
// Return bytes read or -1 if a network error.

int NetRead(int sock_fd, char *Buf, int BufSize)
{
    int RecvTot = 0;
    int RdBytes;
    // response_buf defined earlier as [4096]

    while ((RdBytes =
        recv(sock_fd, Buf + RecvTot, BufSize - RecvTot - 1, 0)) > 0)
    {
        RecvTot += RdBytes;
        if (RecvTot >= BufSize - 1) break;  // Buffer full
    }

    if (RdBytes < 0)
    {
        // Handle actual socket error (e.g., ETIMEDOUT, ECONNRESET)
        PrintErr(WARN, "Whois recv failed\n");
        return -1;
    }

    Buf[RecvTot] = '\0';   // make sure buffer is null terminated


    return(RecvTot);
}



// Queries RADb for a single IP and extracts its netblock
// Returns Number of bits in netblock, otherwise 0.
// If out_ip is not null, it will be set with the netblock base

int query_radb_netblock(char *ip_address, IPTYPE *ip)
{
    int bits;
    char query_buf[64];
    char response_buf[4096] = {0};
    int bytes_received;
    char *route_ptr;
    size_t len;
    int sock_fd;

    if (!ip_address || ip_address[0] == 0 || !ip) return(0);

    // Initialize the connection
    sock_fd = connect_to_server(RADB_HOST, RADB_PORT);
    if (sock_fd < 0) return(0);

    // Construct the query: "-l <ip>\n" ('l' = lower case L)
    snprintf(query_buf, sizeof(query_buf) - 1, "-l %s\n", ip_address);
//    PrintErr(STATUS, "Sending: %s\n", query_buf);

    // Send the query over our open persistent socket
    if (send(sock_fd, query_buf, strlen(query_buf), 0) < 0)
    {
        PrintErr(WARN, "Socket send failed.\n");
        CLOSE_SOCKET(sock_fd);
        return(0);
    }

    // Read response back from the socket
    memset(response_buf, 0, sizeof(response_buf));
    bytes_received = NetRead(sock_fd, response_buf, sizeof(response_buf));

    CLOSE_SOCKET(sock_fd);
    if (bytes_received <= 0) return(0);


    // Parse what we got (which is null terminated text)

//    PrintErr(STATUS, "Recv'd %d bytes.\n", bytes_received);

    // Look for the "route:" label inside RADb's text response
    route_ptr = strstr(response_buf, "route:");
    if (!route_ptr)
    {
        PrintErr(WARN, "Route not found.\n");
        return(0);
    }

    route_ptr += 6;  // Move pointer past "route:"
    route_ptr += strspn(route_ptr, " \t\b"); // skip blanks, tabs, backspaces
    len = strspn(route_ptr, "0123456789./");  // get length of address
    route_ptr[len] = '\0';   // Chop off at end

    bits = Str2Ip(route_ptr, ip);  // Parse to DWORD

//    if (bits)
//        PrintErr(STATUS, "Found CIDR Block: %s\n", IP2Str(ip->IP, ip->bits));

    return (bits);
}


