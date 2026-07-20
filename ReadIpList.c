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

// This module reads the main IP list.

#include "AutoBlock.h"



// =============================================================================
// IP PARSING UTILITY
// =============================================================================


// Convert text ip into dword.  Return netblock bits.
// Return zero on error.

int Str2Ip(const char *ip_str, IPTYPE *ip)
{
    unsigned int o1, o2, o3, o4;
    unsigned int bits = 32; // Default to /32 if no slash is provided
    int matched;

    if (!ip_str || !ip) return 0;

    // initialize
    ip->IP = 0;
    ip->bits = 0;

    // The "%u.%u.%u.%u/%u" string tries to read 4 octets and an optional slash value
    matched = sscanf(ip_str, "%u.%u.%u.%u/%u", &o1, &o2, &o3, &o4, &bits);

    if (matched == 4 || matched == 5)
    {
        // Validation check to prevent invalid inputs like 999.999.999.999
        if ((o1 | o2 | o3 | o4) > 0xFF)
        {
            PrintErr(WARN, "Error: Invalid IP octet value in '%s'\n", ip_str);
            return(0);
        }

        // Pack the 4 octets into a single 32-bit DWORD
        ip->IP = (o1 << 24) | (o2 << 16) | (o3 << 8) | o4;

    }
    else
    {
        bits = 0;
    }

    ip->bits = bits;

    return(bits);
}


// Read the ip in whois file format
// XXXX:01.02.03.04/20
// Same as Str2Ip but with preceeding characters.
// Return 0 on error or datestamp if valid.

WORD ReadWhoisIp(const char *ip_str, IPTYPE *ip)
{
    char *ptr;
    DWORD val;

    if (!ip_str) return (0);

    val = strtoul(ip_str, &ptr, 16);
    if (*ptr != ':' || val > 0xFFFF) return(0);      // improper format

    if (Str2Ip(ptr + 1, ip) == 0) return(0);

    return((WORD)(val & 0xFFFF));
}




// =============================================================================
// Read the Whois.txt file to get the previous IP netblocks
// Insert each netblock into trie root.
// Return number of unique IP blocks added to trie.
// =============================================================================

DWORD process_ip_file(const char *filename, TrieNode *root)
{
    FILE *file;
    char line[256];
//    int bits;
    IPTYPE ip;
    size_t len;
    DWORD added = 0;
    WORD DateStamp;

    // Open the file using standard C I/O (works on Windows/Linux)
    file = fopen(filename, "r");
    if (file == NULL)
    {
        PrintErr(WARN, "Error opening file: %s\n", filename);
        return(0);
    }

    // Main loop: Read line by line
    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Remove trailing newline/whitespace
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
        {
            line[len - 1] = '\0';
        }

        // Skip empty lines or comments
        if (line[0] == '\0' || line[0] == '#')
        {
            continue;
        }

        // Expected format: IP/Mask (e.g., 5.135.0.0/16)

        // Convert ASCII IP to DWORD
        DateStamp = ReadWhoisIp(line, &ip);
        if (DateStamp == 0 || ip.bits == 0)
        {
            PrintErr(WARN,
                "Skipping line: Could not parse IP address '%s'.\n", line);
            continue;
        }

        // Call the required function
        // Note: The requirement specifies ip is the DWORD, and blksz
        // is the mask length.
        if (insert_netblock(root, ip, DateStamp)) added++;

//        PrintErr(STATUS, "Reading: %s\n", IP2Str(ip));
    }

    fclose(file);

    return (added);
}


