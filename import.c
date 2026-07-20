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

// This module handles importing public IP lists.

#include "AutoBlock.h"


// Open an url using popen and curl.
// Return a file pointer, or NULL.

FILE *OpenUrl(char *url, int port)
{
    char command[1024];
    FILE *fp;

    // Check for null or invalid inputs
    if (!url || !url[0]) return(NULL);

    // Build the curl execution command string.
    // If a port is specified (> 0), we instruct curl to connect using
    // that explicit port override.
    if (port > 0 && port < 65536)
    {
        sprintf(command,
            "curl -sSf --connect-timeout 10 --port %d %.900s 2>&1",
            port, url);
    }
    else
    {
        sprintf(command,
            "curl -sSf --connect-timeout 10 %.900s 2>&1", url);
    }

    // Open a background pipe to read stdout from the curl process
    fp = popen(command, "r");  // must be "r" not "rb" in linux

    return(fp);  // must be closed with pclose().

}


// Read the imports from the file or url one line at a time and
// then add to G_Imports table.
// Return 0 if ok.

int ReadImports(char *path)
{
    char *pptr, Line[1024];
    bool isUrl;
    int Status, port = 0;
    DWORD iplen;
    IPTYPE ip, *tmpIp;
    FILE *fp;

    if (!path || !path[0]) return(-1);
    isUrl = (bool)(strncmpi(path, "http", 4) == 0);


    // Open URL or file

    if (isUrl)
    {
        pptr = strchr(path + 6, ':');  // look for port number
        if (pptr)   // has a port number
        {
            *pptr = '\0';    // get rid of port num from url
            port = atoi(++pptr);  // get port number
        }
        fp = OpenUrl(path, port);
    }
    else
    {
        fp = fopen(path, "rb");
    }

    if (!fp) return(-1);

    PrintErr(STATUS, "Importing: %s\n", path);

    // Process lines
    while (fgets(Line, sizeof(Line), fp) != NULL)
    {
        // Truncate at the first occurrence of \r, \n, or #
        Line[strcspn(Line, "\r\n#")] = '\0';
        trim(Line);    // remove leading and trailing white space
        iplen = strspn(Line, "0123456789./");

        // Check if the line is empty (e.g., it was a comment line)
        if (Line[0] == '\0' || iplen != strlen(Line))
        {
            continue;    // Line is not a valid IP
        }

        // Convert to IPTYPE
        if (Str2Ip(Line, &ip) == 0) continue;   // not a valid IP

        // make room for one more
        tmpIp = (IPTYPE *) realloc(G_Imports, (G_NumImports + 1) * sizeof(IPTYPE));
        if (!tmpIp)
        {
            PrintErr(FATAL, "Ran out of memory while importing: %s\n", path);
            break;
        }
        G_Imports = tmpIp;
        G_Imports[G_NumImports++] = ip;

    }

    // Close url or file
    Status = (isUrl) ? pclose(fp) : fclose(fp);

    return (Status);
}


// Import bad IP list from web or file
// Add to trie.
// Returns the number of netblocks actually added to trie.

int ImportIPs(TrieNode* root, WORD DateStamp)
{
    int count, added = 0;
    IPTYPE ip;
    DWORD cidrmask = 0xFFFFFFFF << (32 - G_MaxCidr);

    for (count = 0; count < G_NumImports; count++)
    {
        ip = G_Imports[count];

        // Apply G_MaxCidr
        if (ip.bits > (DWORD) G_MaxCidr)
        {
            ip.bits = G_MaxCidr;
            ip.IP &= cidrmask;
        }

        // Add to trie table
        if (insert_netblock(root, ip, DateStamp)) added++;
    }


    return(added);
}


