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

// This is the main source file for the program.

#include "AutoBlock.h"
#include <stdarg.h>
#include <time.h>

// To compile with gcc, use the following:
// gcc -o AutoBlock AutoBlock.c  Hash-ip.c  ReadIpList.c  ReadMsgs.c  tries.c  whois.c config.c

// To view hacker counts in openwrt:
//   nft list ruleset | grep -A 1 -i "block-attacker"

// Send IP list to openwrt
// Send to "/var/tmp/bad_ips.txt" on asterisk.lan to /etc/blocklist.txt on
// tomato.lan using scp.
//   scp -O /var/tmp/bad_ips.txt root@tomato.lan:/etc/blocklist.txt

// Tun the following to get it to stick:
//   ssh root@tomato.lan '/etc/init.d/firewall reload'

// For duplicate sets in openwrt use the following:
//   nft delete set inet fw4 IncludedIpSet

// If you ssh into openwrt, you can run the following command to list
// the count of blocked attempts:
// nft list ruleset | grep -A 1 -i "block-attacker"

void Send2Router(void)
{
    int status;
    FILE *pfp;
    char buffer[256];

//    sprintf(buffer, "rsync -c %s %s:%s", SRCPATH, DSTSERV, G_FirewallBlockListPath);
    PrintErr(STATUS, "%s\n", G_TransferCmd);
    if (G_DryRun) return;   // don't actually send anything to the router

    pfp = popen(G_TransferCmd, "r");
    buffer[0] = 0;

    // Read the output if you want to log the progress
    while (fgets(buffer, sizeof(buffer), pfp) != NULL)
    {
        PrintErr(STATUS, "rsync: %s\n", buffer);
    }
    status = pclose(pfp);   // close and wait for finish
    if (WEXITSTATUS(status) != 0)
    {
        // Log the error: Transfer failed or firewall reload failed
        PrintErr(FATAL, "Error with File Transfer.\n");
    }


//    sprintf(buffer, "ssh %s '%s'", DSTSERV, DSTLOAD);
    PrintErr(STATUS, "%s\n", G_ReloadCmd);
    status = pclose(popen(G_ReloadCmd, "r"));
    if (WEXITSTATUS(status) != 0)
    {
        // Log the error: Transfer failed or firewall reload failed
        PrintErr(FATAL, "Error restarting firewall.\n");
    }

}

bool ConfigChanged(void)
{
    struct stat config_stat;
    struct stat output_stat;

    int config_rc = stat(CONFIGPATH, &config_stat);
    int output_rc = stat(SRCPATH, &output_stat);

    // If the configuration file itself is missing,
    // we cannot execute or copy anything anyway.
    if (config_rc != 0) return false;

    // FIRST RUN: If the config exists but the history file is missing,
    // this is a brand new installation—force an initial upload.
    if (output_rc != 0) return true;

    // Both files exist cleanly. Check if config is newer.
    if (config_stat.st_mtime > output_stat.st_mtime)
        return true;

    return false;
}

bool is_root(void)
{
#if defined(__BORLANDC__)
    return(true);   // not supported by borland
#else
    return geteuid() == 0;
#endif
}

//Checks if a file is insecure (not owned by root or writeable by others).
//
// @param path The absolute path to the file (e.g., "/etc/AutoBlock.conf").
// @return true if the file is NOT owned by root OR can be modified
// by others.  Returns true on system error (fails safe by treating
// errors as insecure).

bool NotRootOwned(char *path)
{
    if (!path) return(true);
    
#if defined(__BORLANDC__)
    strlen(path);    // remove compiler warning
    return(false);
#else
    struct stat fileStat;

    // Execute system call to read file metadata
    if (stat(path, &fileStat) < 0)
    {
        // Fail-safe: If the file is missing or unreadable, treat it as
        // insecure
        PrintErr(FATAL, "Error reading %s file status.\n", path);
        return true;
    }

    // 1. Check Ownership: Root User ID (UID) is always 0
    if (fileStat.st_uid != 0)
    {
        PrintErr(FATAL, "%s is not owned by root.\n", path);
        return true; // Not owned by root
    }

    // 2. Check Permissions: Ensure nobody else has write permissions
    // S_IWGRP check = Group Write permission bit
    // S_IWOTH check = Others Write permission bit
    if ((fileStat.st_mode & S_IWGRP) || (fileStat.st_mode & S_IWOTH))
    {
        PrintErr(FATAL, "Modifying %s by non-root users must not be allowed.\n", path);
        return true; // Allows modification by group or others
    }

    // The file is fully secure (Owned by Root, Write-restricted)
    return false;
#endif
}



int main(void)
{
    int count, bits, oldbits, i, rt;
    DWORD ip;
    IPTYPE ipBlk;
    TrieNode *TriRoot;
    char *IpStr;
    bool changed=false;


#if defined(__BORLANDC__)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
    {
        PrintErr(FATAL, "Winsock initialization failed.\n");
        return -1;
    }
#endif

    if (!is_root())
    {
        PrintErr(FATAL, "This program must be run as root.\n");
        CLOSE_NETWORK();
        return(-3);
    }

    if (NotRootOwned(CONFIGPATH))
    {
        PrintErr(FATAL, "The config file must only be modifiable by root.\n");
        CLOSE_NETWORK();
        return(-4);
    }

    if (ParseConfig(CONFIGPATH))
    {
        PrintErr(FATAL, "Could not parse \"%s\" config file.\n", CONFIGPATH);
        CLOSE_NETWORK();
        return(-2);
    }

    TriRoot = create_node();  // Create Trie


    // Read existing bad IPs into Trie here
    // Function handles file i/o errors
    PrintErr(STATUS, "Reading existing banned IP blocks.\n");
    process_ip_file(MAINPATH, TriRoot);


    // Read message log
    PrintErr(STATUS, "Reading New IP's from: %s\n", G_AsteriskNoticeFile);
    count = HashMessages();
    if (count >= 0)
        PrintErr(STATUS, "There were %d bad IP's added to the hash table.\n", count);

    // Convert to flat linked list
    count = HashFlat();
    PrintErr(STATUS, "There were %d unique bad IP's in the hash table.\n", count);

    // Read hash table and add to Trie
    count = 0;
    GetNextHash(true);   // initialize the walker
    while ((ip = GetNextHash(false)) != 0)
    {
        if (is_ip_covered(TriRoot, ip)) continue; // already there

        if (G_UseWhois)
        {
            // Use whois to find netblock
            count++;
            ipBlk.IP = ip;
            ipBlk.bits = 0;
            IpStr = IP2Str(ipBlk);
            PrintErr(STATUS, "%d: Whois: %s -> ", count, IpStr);
            bits = query_radb_netblock(IpStr, &ipBlk);
            if (bits)
            {
                PrintErr(STATUS, "%s ", IP2Str(ipBlk));
                changed = true;
            }
            else
            {
                PrintErr(WARN, "Failed.\n");
                continue;    // whois failed for some reason
            }
        }

        // Add directly into Trie
        oldbits = bits;
        if (bits == 0 || bits > G_MaxCidr) bits = G_MaxCidr;
        if (bits < G_MinCidr) bits = G_MinCidr;
        if (oldbits != bits) PrintErr(STATUS, "Cidr Mofified ->(%d)", bits);
        insert_netblock(TriRoot, ipBlk);
        PrintErr(STATUS, "\n");
    }

    PrintErr(STATUS, "There were %d new netbocks added to the blacklist.\n", count);
    destroy_hash_table();   // free hash table

    // Save unmangled netblocks to the history file.
    if (changed)
    {
        PrintErr(STATUS, "Updating main whois file.\n");
        export_netblocks_to_file(TriRoot, MAINPATH);
    }



    PrintErr(STATUS, "Removing whitelist blocks.\n");
    if (G_IgnoreBlocks && G_NumIgnoreBlocks)
    {
        for (i = 0; i < G_NumIgnoreBlocks; i++)
        {
            ipBlk = G_IgnoreBlocks[i];
            rt = whitelist_netblock(TriRoot, ipBlk);
            PrintErr(STATUS, "%s was ", IP2Str(ipBlk));
            PrintErr(STATUS, "%s the blacklist.\n", rt ?
                                "Removed from" : "Not found in");

        }
    }


    CLOSE_NETWORK();




    if (changed || ConfigChanged())
    {
        // Save whitelist mangled trie
        PrintErr(STATUS, "Sending to Router.\n");
        export_netblocks_to_file(TriRoot, SRCPATH);
        Send2Router();
    }
    free_subtree(TriRoot);  // destroy trie


    FreeConfig();   // free the heap

    return(0);

}



//enum {QUIET, FATAL, WARN, STATUS };

void PrintErr(DWORD level, const char *fmt, ...)
{
    va_list args;

    // Print to console if verbose mode is enabled
    if (G_Verbosity >= level)
    {
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        fflush(stdout); // Ensure immediate console output
    }

    // Log to file if the path string is not empty
    if (level < STATUS && G_LogFilePath[0] != '\0')
    {
        FILE *fp = fopen(G_LogFilePath, "at");
        if (fp != NULL)
        {
            time_t rawtime;
            struct tm *timeinfo;

            // Get current system time
            time(&rawtime);
            timeinfo = localtime(&rawtime);

            // Write timestamp prefix: YYYY-MM-DD HH:MM>
            fprintf(fp, "%04d-%02d-%02d %02d:%02d> ",
                    timeinfo->tm_year + 1900,
                    timeinfo->tm_mon + 1,
                    timeinfo->tm_mday,
                    timeinfo->tm_hour,
                    timeinfo->tm_min);

            // Write the formatted error message components
            va_start(args, fmt);
            vfprintf(fp, fmt, args);
            va_end(args);

            fclose(fp);
        }
    }
}




