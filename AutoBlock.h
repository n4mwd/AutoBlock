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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>


#if defined(__BORLANDC__)
  #define CONFIGPATH  "./AutoBlock.conf"  // config location
  #define DEFAULTLOGFILE "./AutoBlock.log"  // default until changed
  #define SRCPATH  "Bad-Ips.txt"         // local bad ip file sent to router
  #define MAINPATH "Whois.txt"  // whois file
#else
  #define CONFIGPATH  "/etc/AutoBlock.conf"  // config location
  #define DEFAULTLOGFILE "/var/log/AutoBlock.log"  // default until changed
  #define SRCPATH  "/root/AutoBlock/Bad-Ips.txt" // local bad ip file sent to router
  #define MAINPATH "/root/AutoBlock/Whois.txt"  // whois file
#endif


#define MIN(X,Y) ((X)<(Y)?(X):(Y))


#if defined(__BORLANDC__)
    #include <winsock.h>
    #define SOCKET_TYPE        SOCKET
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define CLOSE_SOCKET(s)    closesocket(s)
    //#define PRINT_NET_ERROR(m) fprintf(stderr, "%s. Winsock Error: %d\n", m, WSAGetLastError())
    #define snprintf(buf, len, fmt,data) sprintf(buf, fmt, data)
    #define sleep(x)  Sleep(x * 1000)
    #define SetNetTmo(sk, sc) { DWORD timeout = (sc * 1000); \
        setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)); }
    #define CLOSE_NETWORK()  {WSACleanup();}
    #define popen        _popen
    #define pclose       _pclose
    #define WEXITSTATUS(status) status
    //typedef unsigned __int32 DWORD;
    typedef unsigned char BYTE;
    typedef unsigned char bool;
    #define false  0
    #define FALSE  0
    #define true   1
    #define TRUE   1
#else
    #include <stdint.h>
    #include <stdbool.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <sys/wait.h>

    #define SOCKET_TYPE        int
    #define INVALID_SOCKET_VAL -1
    #define CLOSE_SOCKET(s)    close(s)
    //#define PRINT_NET_ERROR(m) perror(m)
    #define SetNetTmo(sk, sc) { struct timeval tv = {sc, 0};  \
        setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)); }
    #define CLOSE_NETWORK()    {/* */}
    #define snprintf snprintf
    typedef uint32_t DWORD;
    typedef uint8_t  BYTE;
#endif

#define HASH_SIZE  256     // size of hash table
#define PATH_SIZE  512     // File/cmd path length
// Definition of Bitmask Positions
#define BIT_NOTICE                  ((DWORD)(1 << 0)) // 0x01
#define BIT_REGISTER                ((DWORD)(1 << 1)) // 0x02
#define BIT_INVITE                  ((DWORD)(1 << 2)) // 0x04
#define BIT_OPTIONS                 ((DWORD)(1 << 3)) // 0x08
#define BIT_ID_IS_ALPHA             ((DWORD)(1 << 4)) // 0x10
#define BIT_ID_IS_NUM               ((DWORD)(1 << 5)) // 0x20
#define BIT_ADDR_IS_IP              ((DWORD)(1 << 6)) // 0x40
#define BIT_ADDR_IS_NAME            ((DWORD)(1 << 7)) // 0x80
#define BIT_FAILED_FOR              ((DWORD)(1 << 8)) // 0x100
#define BIT_FAILED_TO_AUTHENTICATE  ((DWORD)(1 << 9)) // 0x200
#define BIT_NO_MATCHING_ENDPOINT    ((DWORD)(1 << 10))// 0x400
#define REQTYPE_ALL       (BIT_REGISTER | BIT_INVITE | BIT_OPTIONS)

// Verbosity values
enum {QUIET, FATAL, WARN, STATUS };




// Type definitions

// A binary trie node representing a bit path (0 or 1)
typedef struct TrieNode
{
    struct TrieNode *children[2];
    bool is_block; // Marks if this specific prefix represents an active netblock
} TrieNode;

typedef struct
{
    int first, last;
} RANGE;


typedef struct
{
    DWORD IP;
    DWORD bits;
} IPTYPE;


extern bool    G_DryRun;
extern char    G_LogFilePath[PATH_SIZE];
extern char    G_AsteriskNoticeFile[PATH_SIZE];
extern char    G_FirewallBlockListPath[PATH_SIZE];
extern char    G_TransferCmd[PATH_SIZE];
extern char    G_ReloadCmd[PATH_SIZE];
extern DWORD   G_Verbosity;
extern DWORD   G_RequestTypes;
extern int     G_AllowNamedServer;
extern RANGE  *G_AllowedNumericalIds;
extern int     G_NumAllowedNumericalIds;
extern IPTYPE *G_IgnoreBlocks;
extern int     G_NumIgnoreBlocks;
extern int     G_MinCidr;
extern int     G_MaxCidr;
extern bool    G_UseWhois;




// Test prototypes
int tries_main(void);
int whois_main(void);
int readmsgs_main(void);
int test_parse_ip_string(void);
int readiplist_main(void);
int haship_main(void);


// Functions
void PrintErr(DWORD level, const char *fmt, ...);
void insert_netblock(TrieNode* root, IPTYPE ip);
TrieNode* create_node(void);
int Str2Ip(const char *ip_str, IPTYPE *ip);
char *IP2Str(IPTYPE ip);
DWORD ValidateHacker(char *line, DWORD *flags);
void destroy_hash_table(void);
int HashFlat(void);
int HashMessages(void);
DWORD GetNextHash(int init);
int query_radb_netblock(char *ip_address, IPTYPE *ip);
bool is_ip_covered(TrieNode* root, DWORD ip);
void free_subtree(TrieNode* node);
void export_netblocks_to_file(TrieNode* root, const char* filename);
int process_ip_file(const char *filename, TrieNode *root);
DWORD Domain2Ip(char *str);
int ParseConfig(const char *filepath);
int SearchID(int ext);
void FreeConfig(void);
int whitelist_netblock(TrieNode* root, IPTYPE ip);
bool is_ip_whitelisted(DWORD ip);












