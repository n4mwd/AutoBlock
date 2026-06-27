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

// This module handles reading the asterisk log file.

#include "AutoBlock.h"


/**
 * Parses a single Asterisk log line to extract authentication failure metadata.
 *
 * @param line         [Input]  The raw log line text - must be null terminated.
 * @param out_id       [Output] Buffer to copy the extracted <sip:[id]@...> string. Must be >= 32 bytee.
 * @param out_fail_ip  [Output] Buffer to copy the extracted target "failed for" IP string. Must be >= 32 bytes.
 * @return             A bitmask tracking all components found. Returns 0 if "NOTICE" is missing.
 */
 // out_id must be at least 32 chars.

DWORD parse_asterisk_log_line(char *line, char *out_id, char *out_fail_ip)
{
    DWORD mask = 0;
    const char *request_ptr;
    const char *sip_start;
    const char *host_start;
    const char *at_sign;
    const char *sip_end;
    const char *failed_for_ptr;
    const char *ip_start_quote;
    const char *ip_end_quote;
    const char *port_colon;
    const char *ip_end_boundary;
    size_t host_len;
    size_t span_count;
    size_t ip_len, id_len;

    // Initialize outputs
    if (!line || !out_id || !out_fail_ip) return(0);   // parameters null
    out_id[0] = '\0';      // Must be >= 32 bytes long.
    out_fail_ip[0] = '\0'; // Must be >= 32 bytes long.

    // Check for "NOTICE"
    if (strstr(line, "NOTICE") == NULL)
    {
        return 0; // Return zero immediately if NOTICE is missing
    }
    mask |= BIT_NOTICE;

    // Locate "Request" and verify method types
    request_ptr = strstr(line, "Request");
    if (!request_ptr) return mask;   // These aren't the droid's we're looking for.

    if (strstr(request_ptr, "'REGISTER'") != NULL)
    {
        mask |= BIT_REGISTER;
    }
    else if (strstr(request_ptr, "'INVITE'") != NULL)
    {
        mask |= BIT_INVITE;
    }
    else if (strstr(request_ptr, "'OPTIONS'") != NULL)
    {
        mask |= BIT_OPTIONS;
    }

    // Extract information from the "<sip:" wrapper
    sip_start = strstr(request_ptr, "<sip:");
    if (!sip_start) return mask;

    // Jump past "<sip:"
    sip_start += 5;
    at_sign = strchr(sip_start, '@');
    sip_end = strchr(sip_start, '>');

    if (at_sign && sip_end && at_sign < sip_end)
    {
        // Copy the ID string safely
        id_len = MIN(at_sign - sip_start, 31);
        strncpy(out_id, sip_start, id_len);
        out_id[id_len] = '\0';

        // Check if ID is alpha or digits
        if (strspn(out_id, "0123456789") == id_len)
            mask |= BIT_ID_IS_NUM;
        else if (id_len)
            mask |= BIT_ID_IS_ALPHA;

        // Determine if target host is an IP or Domain URL
        host_start = at_sign + 1;
        host_len = sip_end - host_start;

        // Scan the host segment to see if it only contains dotted IPv4 characters
        span_count = strspn(host_start, "0123456789.");
        mask |= ((span_count == host_len) ? BIT_ADDR_IS_IP : BIT_ADDR_IS_NAME);
    }

    // Check for "failed for" and extract trailing attacking IP address
    failed_for_ptr = strstr(sip_end ? sip_end : request_ptr, "failed for");
    if (failed_for_ptr)
    {
        mask |= BIT_FAILED_FOR;

        // Find the single-quoted string containing the attacker's IP:Port
        ip_start_quote = strchr(failed_for_ptr, '\'');
        if (ip_start_quote)
        {
            ip_start_quote++; // step past opening quote
            ip_end_quote = strchr(ip_start_quote, '\'');

            if (ip_end_quote)
            {
                // Determine length without taking the port (isolate up to the ':')
                port_colon = strchr(ip_start_quote, ':');
                ip_end_boundary = (port_colon && port_colon < ip_end_quote) ? port_colon : ip_end_quote;

                ip_len = MIN(ip_end_boundary - ip_start_quote, 31);
                strncpy(out_fail_ip, ip_start_quote, ip_len);
                out_fail_ip[ip_len] = '\0';
            }
        }
    }

    // Check for terminal authentication signatures
    if (strstr(line, "Failed to authenticate") != NULL)
    {
        mask |= BIT_FAILED_TO_AUTHENTICATE;
    }
    if (strstr(line, "No matching endpoint found") != NULL)
    {
        mask |= BIT_NO_MATCHING_ENDPOINT;
    }

    return mask;
}


// Read and validate a line.
// Return an IP address as a DWORD if IP is a hacker.
// Return zero if a hacker IP was not found.

DWORD ValidateHacker(char *line, DWORD *flags)
{
    DWORD   mask, ext;
    char    idBuf[64];
    char    ipBuf[64];
    int     isHacker = false;
    IPTYPE  ip;


    idBuf[0] = ipBuf[0] = '\0';
    mask = parse_asterisk_log_line(line, idBuf, ipBuf);
    *flags = mask;
    if (!mask) return(0);  // Not a NOTICE

    // Check if we process this request type
    ext = mask & G_RequestTypes;
    if (ext == 0) return(0); // We don't process this notice

    // Is the asterisk server specified by domain name
    if (mask & BIT_ADDR_IS_NAME && G_AllowNamedServer)
    {
        if (G_AllowNamedServer > 0)
            G_AllowNamedServer--;   // decrement until false
        return(0);    // they know us
    }

    if (!(mask & BIT_FAILED_TO_AUTHENTICATE) && !(mask & BIT_NO_MATCHING_ENDPOINT) )
        return(0);   // Unrecognized error

    // Check to see if a numerical id is allowed
    if (mask & BIT_ID_IS_NUM)
    {
        ext = atoi(idBuf);
        isHacker = SearchID(ext);  // Search G_AllowedNumericalIds
        // isHacker is TRUE if numerical ID not allowed
    }

    if ((mask & BIT_ADDR_IS_IP) && (mask & BIT_FAILED_FOR))
        isHacker = true;

    if (isHacker && ipBuf[0])   // return the hacker's IP address
    {
        Str2Ip(ipBuf, &ip);
        if (ip.bits == 32) return(ip.IP);
    }

    return(0);    // Not enough evidence
}

// Format a DWORD into standard dotted-decimal ASCII format
// Return pointer to static string.  Not thread safe!
// Pass 0 for bits if no block

char *IP2Str(IPTYPE ip)
{
    static char IpStr[64];
    DWORD ipval = ip.IP;

    BYTE octet1 = (BYTE)((ipval >> 24) & 0xFF);
    BYTE octet2 = (BYTE)((ipval >> 16) & 0xFF);
    BYTE octet3 = (BYTE)((ipval >> 8) & 0xFF);
    BYTE octet4 = (BYTE)(ipval & 0xFF);

    if (ip.bits)   // cidr format
        sprintf(IpStr, "%d.%d.%d.%d/%d", octet1, octet2, octet3, octet4, ip.bits);
    else   // single IP format
        sprintf(IpStr, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);

    return(IpStr);
}




