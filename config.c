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

#include "AutoBlock.h"


/*
 * config.c
 * Parses the AutoBlock configuration file and sets global variables.
 *
 */

// This module handles processing of the conf file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


/* --------------------------------------------------------------------------
 * Global variables
 * -------------------------------------------------------------------------- */
bool    G_DryRun                    = false;
char    G_LogFilePath[PATH_SIZE]    = DEFAULTLOGFILE;
char    G_AsteriskNoticeFile[PATH_SIZE] = {0};
char    G_FirewallBlockListPath[PATH_SIZE]= {0};
char    G_TransferCmd[PATH_SIZE]    = {0};
char    G_ReloadCmd[PATH_SIZE]      = {0};
DWORD   G_Verbosity                 = STATUS;
DWORD   G_RequestTypes              = 0;
int     G_AllowNamedServer          = 0;   // 0=FALSE, -1=TRUE, count
RANGE  *G_AllowedNumericalIds       = NULL;
int     G_NumAllowedNumericalIds    = 0;
IPTYPE *G_IgnoreBlocks              = NULL;
int     G_NumIgnoreBlocks           = 0;
int     G_MinCidr                   = 0;
int     G_MaxCidr                   = 32;
bool    G_UseWhois                  = true;


static char *Continued = NULL;      // buffer for joined continuation lines
static int  ContBufLen = 0;         // Length of continuation buffer
static DWORD SeenFlags = 0;


/* ==========================================================================
 * FreeConfig
 *
 * Releases any heap memory allocated by ParseConfig().
 * ========================================================================== */
void FreeConfig(void)
{
    if (G_AllowedNumericalIds)
    {
        free(G_AllowedNumericalIds);
        G_AllowedNumericalIds    = NULL;
        G_NumAllowedNumericalIds = 0;
    }

    if (G_IgnoreBlocks)
    {
        free(G_IgnoreBlocks);
        G_IgnoreBlocks    = NULL;
        G_NumIgnoreBlocks = 0;
    }

    if (Continued)
    {
        free(Continued);
        Continued = NULL;
        ContBufLen = 0;         // Length of continuation buffer
    }

}

/* --------------------------------------------------------------------------
 * Internal helper: trim leading and trailing whitespace in-place.
 * Returns pointer to the first non-whitespace character in s.
 * -------------------------------------------------------------------------- */
static char *trim(char *s)
{
    char *end;
    int  len;

    // first trim trailing spaces newlines and line feeds
    if (!s) return(NULL);
    for (end = s + strlen(s) - 1; end >= s; end--)
    {
        if (isspace((unsigned char) *end)) *end = '\0';
        else break;
    }

    // remove leading white space
    end = s + strspn(s, " \t\v\f");
    len = strlen(end) + 1;
    // Note that there is a bug in the gcc library for strcpy().  In K&R,
    // opverlapping strings copied right to left are supporsed to work
    // properly.  They do not with gcc.  You have to use memmove().
    if (end != s) memmove(s, end, len);
//    if (end != s) strcpy(s, end);   // won't work with gcc.


    return(s);
}



// Strip line of comments, CR, and LF.
// Convert tabs, form feeds, and vertical feeds to regular spaces

char *StripComments(char *s)
{
    char *p;
    
    for (p = s; *p; p++)
    {
        if (*p == '#' || *p == '\r' || *p == '\n')   // end of line chars
        {
            *p = 0;
            break;
        }
        else if (*p == '\v' || *p == '\f' || *p == '\t') *p = ' ';    // change to spaces
    }
    
    return(s);
}

/* --------------------------------------------------------------------------
 * Internal helper: convert string to uppercase in-place.
 * -------------------------------------------------------------------------- */

#if !defined(__BORLANDC__)
static void strupr(char *s)
{
    for (; *s; s++)
    {
        *s = toupper((unsigned char) *s);
    }
    return;
}
#endif


// Return 0 if "FALSE", 1 if "TRUE", or -1 if neither

static int GetBoolParam(const char *s)
{
    strupr((char *) s);
    if (strcmp(s, "TRUE") == 0)  return(1);
    if (strcmp(s, "FALSE") == 0) return(0);
    return(-1);   // neither
}


// Return pointer to a path.  Remove optional quotes.
//  If quotes are used, then only the part inside those quotes are returned.
//  If quotes are used and the terminating quote is not present, then return
//  empty string.
// NOTE: That paths may not contain backslashes.  Backslashes are the
//  continuation character.
// NOTE2: Because Linux is case sensitive, the path cannot be changed to
//  upper case.

static void GetConfigPath(char *s, char *buf, int bufsize)
{
    char *q, *t, qc;

    q = strpbrk(s, "\"'`");   // find a quote or null
    if (q)   // has quotes
    {
        qc = *q;   // save quote char so we can find its match
        for (t = s; t <= q; t++) *t = ' ';  // any chars before and including the quote are padded
        q = strchr(q + 1, qc);    // find match
        if (q)                   // found match
        {
            *q = '\0';          // terminate string there
            trim(s);            // get rid of leading spaces
            // Quotes are gone and only that which was inside them remain
        }
        else     // no matching quote
        {
            s[0] = '\0';   // This will cause the following code to return an empty string.
            PrintErr(WARN, "No matching quote in path:%s\n", s);
        }
    }
    strncpy(buf, s, bufsize - 1);
    buf[bufsize - 1] = '\0';
}



// Read a line from the file, pre-process it and return a continuous line
//  that has no leading or trailing spaces and has comments and newlines
//  stripped out.  Line continuations are handle here.
// A pointer to a complete usable line is returned or NULL if there is an
//  error or EOF.

#define LINEBLOCKSIZE      1024

char *GetPreProcessedLine(FILE *fp)
{
    char *s, *p, *NewCont;
    int len;

    if (!fp) return(NULL);

    // make sure the buffer has a minimal size
    if (!Continued)    // line buffer not allocated yet
    {
        ContBufLen = LINEBLOCKSIZE;
        Continued = malloc(LINEBLOCKSIZE);     // start with 1024 bytes
        if (!Continued)
        {
            PrintErr(FATAL, "Insufficient memory!\n");
            return(NULL);          // not enough memory
        }
    }
    Continued[0] = '\0';     // clear old buffer
    s = Continued;           // s is the working line buffer pointer

    while (fgets(s, LINEBLOCKSIZE, fp) != NULL)
    {
        // strip comments and leading and trailing spaces
        StripComments(s);
        trim(s);

        // Check for continuation backslash, if there, remove and retrim.
        // check for continuation character - only one allowed per line
        p = strchr(s, '\\');
        if (p)   // get rid of backslash and re-trim line.
        {
            // This line is continued on the next physical line
            *p = ' ';     // convert backslash to a space
            // Remove spaces between the '\' and the last char before it
            trim(s);      // trim again

            // add free space that goes in between lines if not an empty line
            if (s[0]) strcat(s, " ");
        }
        else
        {
            // This line is not continued, but could be the last line of
            //   other continued lines
            if (Continued[0] == '\0')   // Whole line is a Blank line
            {
                s = Continued;   // start over with fresh line
                continue;     // Don't return blank lines
            }
            return(Continued);   // return entire line
        }

        // If we are here, then we have another line that needs to be
        //   read, so prepare for it.

        len = strlen(Continued);   // get bytes currently used plus terminator

        // make sure that continuation buffer is big enough
        if (ContBufLen < len + LINEBLOCKSIZE + 1)
        {
            // make sure there is enough room
            ContBufLen += LINEBLOCKSIZE;
            NewCont = realloc(Continued, ContBufLen);
            if (!NewCont)   // not enough memory - return what we have
            {
                PrintErr(FATAL, "Insufficent Memory!");
                ContBufLen -= LINEBLOCKSIZE;
                return(Continued);   // No memory left - Return what we have
            }
            Continued = NewCont;
        }
        s = Continued + len; // s points to the '\0' of existing line

        // go back up and read the continued line
    }

    // If we are here, it means that there are no more physical lines in the
    //  file, so we output what we have

    // No more lines in file, but might still have one in buffer
    return(Continued[0] ? Continued : NULL);

}



// Parse the line into an array of string pointers pointing to tokens in
//  the line (now null terminated).  Caller must free() the returned array
//  before GetPreProcessedLine() gets called again.
// The returned value will be NULL if there was a problem.
// The first token will be the variable name before the ':'.
// The additional tokens will be the parameters.

char **ParseConfigLine(char *line)
{
    int i, count = 0;
    char **tokens;
    char *p;

    if (!line || !line[0]) return NULL;

    // Count tokens (Variable Name + Parameters)
    // Syntax: Variable:Param1,Param2,Param3
    // The following for loop might over count, but that's OK

    for (i = 0; line[i] != '\0'; i++)
    {
        if (line[i] == ':' || line[i] == ',') count++;
    }

    if (count == 0) return NULL;

    // The for loop will miss the last token in the line because it doesn't
    //  have a deliminator at the end.  We add one for that to the count,
    //  plus an extra one for the NULL at the end of the list.
    // Yes, I know this is prone to over counting, but that's OK.
    count += 2;

    // Allocate array of pointers
    tokens = (char **)malloc((count) * sizeof(char *));
    if (!tokens) return NULL;
    memset(tokens, 0, count * sizeof(char *));  // make sure it starts fresh

    // Tokenize with strtok().
    // Yes I know that strtok() is not thread safe, but this program has
    //   only one thread so its OK.

    p = strtok(line, ":");    // get first token (the variable)
    tokens[0] = p;
    count = 1;

    while (p != NULL)
    {
        p = strtok(NULL, ",");
        tokens[count++] = p;
    }

    // When there are no more tokens, strtok() returns NULL which is
    //  automatically set to the last entry in tokens[].

    // After tokenizing...
    for (i = 0; tokens[i] != NULL; i++)
    {
        // trim leading and trailing spaces from token
        trim(tokens[i]);
    }

    return tokens;
}


// Search approved variables for Token and return index to that token.
// Return -1 if not found.

// Note that the order of this enum and the table below must be in sync.
enum
{
    DRYRUN=0, VERBOSITY, LOGFILEPATH, ASTERISKNOTICEFILE,
    FIREWALLBLOCKLISTPATH, REQUESTTYPES, ALLOWNAMEDSERVER,
    ALLOWEDNUMERICALIDS, IGNOREBLOCKS, MINCIDR, MAXCIDR, USEWHOIS,
    TRANSFERCMD, RELOADCMD, VARIABLE_COUNT
};

int GetVariable(char *Token)
{
    int i;
    // This table must match the above enum exactly.
    static const char *vars[] =
    {
        "DRYRUN",
        "VERBOSITY",
        "LOGFILEPATH",
        "ASTERISKNOTICEFILE",
        "FIREWALLBLOCKLISTPATH",
        "REQUESTTYPES",
        "ALLOWNAMEDSERVER",
        "ALLOWEDNUMERICALIDS",
        "IGNOREBLOCKS",
        "MINCIDR",
        "MAXCIDR",
        "USEWHOIS",
        "TRANSFERCMD",
        "RELOADCMD",
        NULL
    };

    strupr(Token);    // convert to uppercase for comaparison

    for (i = 0; vars[i]; i++)
    {
        if (strcmp(vars[i], Token) == 0)
            return(i);
    }

    return(-1);   // didn't find it

}


// Process REQUESTTYPES and return a flag
// Since this parses multiple parameters, the entire token table needs
//  to be passed in.  The flag returned is a bitfield indicating which
//  Request Types are specified.

DWORD ProcessRequestTypes(char **Tokens)
{
    static char *pTab[5] =
    {
        "REGISTER",
        "INVITE",
        "OPTIONS",
        "*",
        NULL
    };

    DWORD fTab[5] =  // This must match pTab[] exactly
    {
        BIT_REGISTER,
        BIT_INVITE,
        BIT_OPTIONS,
        ( BIT_REGISTER | BIT_INVITE | BIT_OPTIONS),
        0
    };

    int i, pn;   // parameter number
    DWORD flags = 0;

    if (!Tokens) return(0);

    // check each parameter
    for (pn = 1; Tokens[pn]; pn++)
    {
        strupr(Tokens[pn]);    // make sure its uppercase
        for (i = 0; pTab[i]; i++)
        {
            if (strcmp(Tokens[pn], pTab[i]) == 0)
            {
                flags |= fTab[i];
                break;
            }
        }
        // if the parameter isn't matched, then don't change flags
    }

    return(flags);
}


DWORD GetVerbosity(char *Token)
{
    static const char *pTab[5] =
    {
        "QUIET",
        "FATAL",
        "WARN",
        "STATUS",
        NULL
    };


    int i;

    if (!Token) return(0);

    strupr(Token);    // make sure its uppercase
    for (i = 0; pTab[i]; i++)
    {
        if (strcmp(Token, pTab[i]) == 0)
            return(i);
    }

    PrintErr(QUIET, "Verbosity cannot be set to: %s\n", Token);
    return(STATUS);   // return this if the token isn't found.
}


// Creates a table at G_AllowedNumericalIds and then processes ranges
//  into RANGE elements of that table.  Sets G_NumAllowedNumericalIds
//  to the number of ranges in the table.

void ProcessAllowedIds(char **Tokens)
{
    int numRanges, np;
    char *tk, *pd;

    // check if this isn't the first time here
    if (G_AllowedNumericalIds)
    {
        free(G_AllowedNumericalIds);   // free old ones, new ones overwrite
        G_AllowedNumericalIds = NULL;
        G_NumAllowedNumericalIds = 0;
    }

    // count the number of ranges we have
    for (numRanges = 0; Tokens[numRanges + 1]; numRanges++);
    if (!numRanges) return;     // no ranges to process

    // Allocate new table
    G_AllowedNumericalIds = malloc(numRanges * sizeof(RANGE));
    memset(G_AllowedNumericalIds, 0, numRanges * sizeof(RANGE));
    G_NumAllowedNumericalIds = numRanges;

    // Note if the syntax is correct, the following will work
    for (np = 0; (tk = Tokens[np + 1]) != NULL; np++)
    {
        // Get token range
        G_AllowedNumericalIds[np].last =       // get first part and
        G_AllowedNumericalIds[np].first = atoi(tk);   //store in both
        pd = strchr(tk, '-');    // look for a dash
        if (pd)      // found dash - we have a second part
        {
            G_AllowedNumericalIds[np].last = atoi(pd + 1);  // Get the last part after the dash
        }

        // check to make sure they aren't reversed
        if (G_AllowedNumericalIds[np].first > G_AllowedNumericalIds[np].last)
            PrintErr(WARN, "ID Range has bad order.\n");
    }
}



// Create a table of G_NumIgnoreBlocks IPTYPE blocks at G_IgnoreBlocks.
//  Process IP's, IP cidr, and domain names.  Note that the domain name
//  lookup is done at the start of each run so this works great for
//  whitelisting people with DDNS domain names that change frequently.

void ProcessIgnoredBlocks(char **Tokens)
{
    int numBlocks, cnt, np;
    char *tk, *p;
    IPTYPE ip;
    bool isDom;

    // check if this isn't the first time here
    if (G_IgnoreBlocks)
    {
        free(G_IgnoreBlocks);   // free old ones, new ones overwrite
        G_IgnoreBlocks = NULL;
        G_NumIgnoreBlocks = 0;
    }

    // count the number of blocks we have
    for (numBlocks = 0; Tokens[numBlocks + 1]; numBlocks++);
    if (!numBlocks) return;     // no blocks to process

    // Allocate new table
    G_IgnoreBlocks = malloc(numBlocks * sizeof(IPTYPE));
    memset(G_IgnoreBlocks, 0, numBlocks * sizeof(IPTYPE));

    // Note if the syntax is correct, the following will work
    isDom = false;
    cnt = 0;
    for (np = 0; (tk = Tokens[np + 1]) != NULL; np++)
    {
        // Find cidr block if there
        p = strchr(tk, '/');
        if (p)
        {
            *p = '\0';
            p++;
        }

        // Get Block
        if (Str2Ip(tk, &ip) == 0)   // The parameter is a domain name
        {
            ip.IP = Domain2Ip(tk);
            ip.bits = 32;
            isDom = true;
        }

        // If we have a valid IP, then store it
        if (ip.IP)   // non-zero is good
        {
            ip.bits = (p && p[0]) ? atoi(p) : 32;
            G_IgnoreBlocks[cnt++] = ip;
            PrintErr(STATUS, "WhiteListing: %s", IP2Str(ip));
            if (isDom)  // domain name
                PrintErr(STATUS, " (%s)", tk);
            PrintErr(STATUS, "\n");
        }
        else
        {
            PrintErr(WARN, "Failed to extract IP from: %s\n", tk);
        }
    }
    G_NumIgnoreBlocks = cnt;    // return actual count of valid IP blocks
}


// Search the G_AllowedNumericalIds table for the extension
// Return TRUE if NOT found.

int SearchID(int ext)
{
    int i;

    for (i = 0; i < G_NumAllowedNumericalIds; i++)
    {
        if (ext >= G_AllowedNumericalIds[i].first &&
            ext <= G_AllowedNumericalIds[i].last)
                return(false);  // found it
    }
    return(true);
}


// Starting with G_TransferCmd[PATH_SIZE],
// Replace "%src%" with the local ipset path (SRCPATH).
// Replace "%dst%" with the path to the ipset on the router
//    (G_FirewallBlockListPath[PATH_SIZE]).
// "%%" is replaced with "%".



void ProcessTransferCmd(void)
{
    char TempStr[sizeof(G_TransferCmd)] = {0};
    char *src = G_TransferCmd;
    char *dst = TempStr;
    size_t max_len = sizeof(TempStr) - 1;
    size_t current_len = 0;

    int lenSrc = strlen(SRCPATH);
    int lenDst = strlen(G_FirewallBlockListPath);

    while (*src != '\0')
    {
        // Safety guard to guarantee we never overflow TempStr
        if (current_len >= max_len) break;

        if (*src == '%')
        {
            if (strncmp(src, "%src%", 5) == 0)
            {
                if (current_len + lenSrc < max_len)
                {
                    strcpy(dst, SRCPATH);
                    dst += lenSrc;
                    current_len += lenSrc;
                }
                src += 5; // Advance past the whole token "%src%" cleanly
            }
            else if (strncmp(src, "%dst%", 5) == 0)
            {
                if (current_len + lenDst < max_len)
                {
                    strcpy(dst, G_FirewallBlockListPath);
                    dst += lenDst;
                    current_len += lenDst;
                }
                src += 5; // Advance past the whole token "%dst%" cleanly
            }
            else if (*(src + 1) == '%')
            {
                *dst++ = '%';
                current_len++;
                src += 2; // Skip both percent symbols "%%"
            }
            else
            {
                // Unrecognized token (e.g. "%unknown%").
                // Skips the isolated '%' to match your original discarding logic.
                src++;
            }
        }
        else
        {
            *dst++ = *src++;
            current_len++;
        }
    }
    *dst = '\0'; // Ensure string termination

    // copy back to G_TransferCmd
    strncpy(G_TransferCmd, TempStr, sizeof(G_TransferCmd) - 1);
    G_TransferCmd[sizeof(G_TransferCmd) - 1] = '\0';
    PrintErr(STATUS, "Cmd: %s\n", G_TransferCmd);
}








/* ==========================================================================
 * ParseConfig
 *
 * Opens and processes the configuration file at 'filepath'.
 * Returns 0 on success, non-zero on error.
 * ========================================================================== */

int ParseConfig(const char *filepath)
{
    /* Variables must be declared at the top of the block (ANSI C89) */
    FILE   *fp;
    char  **tokens;
    int     TokenNum, b;
    DWORD   mask;
    char   *p;

    fp = fopen(filepath, "rt");
    if (!fp)
    {
        PrintErr(FATAL, "ParseConfig: cannot open '%s'\n", filepath);
        return 1;
    }


    while ((p = GetPreProcessedLine(fp)) != NULL)
    {
        tokens = ParseConfigLine(p);
        if (!tokens) continue;        // no tokens found
        TokenNum = GetVariable(tokens[0]);
        if (TokenNum == -1)
        {
            PrintErr(WARN, "Unknown Variable: %s\n", tokens[0]);
            free(tokens);
            continue;     // not a valid token
        }

        // Mark that each variable is set
        SeenFlags |= (DWORD)(1 << TokenNum);

        switch (TokenNum)
        {
            // Booleans
            case DRYRUN:
                b = GetBoolParam(tokens[1]);
                if (b == -1) PrintErr(WARN, "Invalid boolean: %s\n", tokens[1]);
                G_DryRun = (bool) b;
                break;

            case USEWHOIS:
                b = GetBoolParam(tokens[1]);
                if (b == -1) PrintErr(WARN, "Invalid boolean: %s\n", tokens[1]);
                G_UseWhois = (bool) b;
                break;

            case VERBOSITY:
                G_Verbosity = GetVerbosity(tokens[1]);
                break;

            // Paths
            case LOGFILEPATH:
                GetConfigPath(tokens[1], G_LogFilePath, sizeof(G_LogFilePath));
                break;

            case ASTERISKNOTICEFILE:
                GetConfigPath(tokens[1], G_AsteriskNoticeFile, sizeof(G_AsteriskNoticeFile));
                break;

            case FIREWALLBLOCKLISTPATH:
                GetConfigPath(tokens[1], G_FirewallBlockListPath, sizeof(G_FirewallBlockListPath));
                break;

            // Cidr sizes
            case MINCIDR:
                G_MinCidr = atoi(tokens[1]);
                if (G_MinCidr <  1) G_MinCidr = 1;
                if (G_MinCidr > 31) G_MinCidr = 31;
                break;

            case MAXCIDR:
                G_MaxCidr = atoi(tokens[1]);
                if (G_MaxCidr <  2) G_MaxCidr = 2;
                if (G_MaxCidr > 32) G_MaxCidr = 32;
                break;

            // This is a non-standard BOOL, FALSE = 0, TRUE= -1, or
            //  a count which can be up to 100,000.
            case ALLOWNAMEDSERVER:

                b = GetBoolParam(tokens[1]);
                if (b == 1) b = -1;  // TRUE
                else if (b == -1)    // not TRUE or FALSE, probably a count
                {
                    b = atoi(tokens[1]);   // its a count
                    if (b < 1) b = 1;
                    if (b > 100000) b = 100000;
                }
                G_AllowNamedServer = b;
                break;


            // The following variables are more complicated because
            //  they allow multiple parameters

            // The sip request type can be "REGISTER", "INVITE", or
            //   "OPTIONS".  Set flag accordingly.
            case REQUESTTYPES:
                G_RequestTypes = ProcessRequestTypes(tokens);
                break;


            // ALLOWEDNUMERICALIDS is a list of Integer ranges stored
            //  as RANGE types.  If a NOTICE arrives with a numerical ID
            //  that is in the range specified, then it is not blocked
            //  right away.
            case ALLOWEDNUMERICALIDS:
                ProcessAllowedIds(tokens);
                break;


            // IGNOREBLOCKS is essentiallly a whitelist.  Here IP's, Cidr
            //   Blocks, and domain names can be listed that cause the
            //   program to ignore errors from the listed IP's.  For
            //   efficiency, make cidr blocks as large as reasonable.
            case IGNOREBLOCKS:
                ProcessIgnoredBlocks(tokens);
                break;

            case TRANSFERCMD:
                GetConfigPath(tokens[1], G_TransferCmd, sizeof(G_TransferCmd));
                ProcessTransferCmd();
                break;

            case RELOADCMD:
                GetConfigPath(tokens[1], G_ReloadCmd, sizeof(G_ReloadCmd));
                break;

            default:
                PrintErr(WARN, "Unknown Variable: %s\n", tokens[0]);
                break;


        } // end switch


        // Free token array
        free(tokens);

        // Unknown tokens are silently ignored

    }  // end while

    fclose(fp);


    // Check if we have seen all variables

    mask = (VARIABLE_COUNT >= 32) ? 0xFFFFFFFF : (1UL << VARIABLE_COUNT) - 1;
    if ((SeenFlags & mask) != mask)
    {
        PrintErr(WARN, "Error: Not all variables set.\n");
    }


    // Cross-validate MINCIDR < MAXCIDR
    if (G_MinCidr >= G_MaxCidr)
    {
        PrintErr(WARN, "Config error: MINCIDR (%d) must be less than MAXCIDR (%d)\n",
                G_MinCidr, G_MaxCidr);
        // Set to safe defaults
        G_MinCidr = 16;
        G_MaxCidr = 24;
    }

    

    return 0;
}



