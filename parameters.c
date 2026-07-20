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

// This module handles command line parameters.

#include "AutoBlock.h"

/* Functional function pointer type definition */
typedef int (*CmdFunc)(char *);

/* Function table entry structure */
typedef struct
{
    const char *cmd_name;
    CmdFunc func_ptr;
} CmdTableEntry;

/*
Command line Parameters

--help, -help, -h  Prints out helpful information.
-dryrun, -d  [true|false] : Overrides conf file DRYRUN setting.  Forces DRYRUN mode to parameter, default=true.
-remove, -r <dotted IPv4 address | domain> :  Removes from whois list immediately.  Not a whitelist.  Can be added again later.
-check, -c <dotted IPv4 address | domain> :  Check to see if the IP is in the whois list.
-purge, -p <days> :    Purges whois entries older than <days>
-version, -v  : Prints the version number.
-verbosity, -V : <quiet, fatal, warn, status> Change the verbosity.
*/

enum {CHECKIP=0, PURGE, REMOVE };

// Process the whois file for the parameter.
// ipStr is a string with either a dotted IPv4 string
// or a domain name.  Cidr's are not permitted.
// mode is 0 for check, 1 for purge, 2 for remove.

int ProcessParameter(char *ipStr, int mode)
{
    char Line[1024], tmpName[512];
    WORD IpDate, DateStamp, days, count = 0;
    IPTYPE ipW, ipN;
    FILE *fp, *fpout = NULL;
    bool NeedOutput;

    if (!ipStr || mode < 0 || mode > 2) return(1);

    if (mode == PURGE)    // ipStr is days in PURGE mode
    {
        days = (WORD) strtoul(ipStr, NULL, 10);
        if (days <= 0 || days > 32000) days = 30;   // default
    }
    else   // other modes treat this as an IP or domain name
    {
        // Get IPTYPE from ip string or domain string
        if (Str2Ip(ipStr, &ipN) == 0)
        {
            // Not an IP string if here, look up domain
            ipN.IP = Domain2Ip(ipStr);
            ipN.bits = 32;
            if (ipN.IP == 0)
            {
                printf("Failed to resolve: %s\n", ipStr);
                return(1);  // did not resolve
            }
        }
    }

    NeedOutput = (bool)(mode > 0);
    DateStamp = GetDateStamp();   // get current day

    fp = fopen(MAINPATH, "rt");
    if (!fp)
    {
        printf("Could not open: %s\n", MAINPATH);
        return(1);
    }

    if (NeedOutput)   // open output file
    {
        // create temporary file name
        sprintf(tmpName, "%.500s.temp$", MAINPATH);

        fpout = fopen(tmpName, "wt");
        if (!fpout)
        {
            fclose(fp);
            return(1);
        }
    }

    while (fgets(Line, sizeof(Line), fp) != NULL)
    {
        IpDate = ReadWhoisIp(Line, &ipW);
        if (IpDate == 0)  // comment
        {
            if (fpout) fputs(Line, fpout);  // rewrite comment
            continue;
        }

        if (mode == PURGE)  // purge past date
        {
            // skip if ipdate is more than days old
            if (IpDate + days < DateStamp)
            {
                count++;
                continue;
            }
        }
        else    // CHECKIP or REMOVE
        {
            if (IpMaskMatch(ipW, ipN.IP))  // found it
            {
                if (mode == CHECKIP)
                {
                    printf("%s is being blocked ", IP2Str(ipW));
                    printf("which includes %s\n", IP2Str(ipN));
                    count++;
                    break;
                }
                else if (mode == REMOVE)
                {
                    printf("%s has been removed.\n", IP2Str(ipW));
                    count++;
                    continue;
                }
            }
        }


        if (fpout)   // write output file
        {
            fprintf(fpout, "%04X:%s\n", IpDate, IP2Str(ipW));
        }
    }

    fclose(fp);

    // If we wrote an output file, we need to rename it.
    if (fpout)
    {
        fclose(fpout);
        remove(MAINPATH);
        rename(tmpName, MAINPATH);
    }
    if (mode == PURGE)
        printf("%u IP Blocks older than %d days have been removed.\n", count, days);
    else if ((mode == CHECKIP || mode == REMOVE) && count == 0)
        printf("%s was not found.\n", ipStr);

    return(1);
}


static int ShowHelp(char *notUsed)
{
    char *HelpStr = "Command line Parameters\n\n"
        "--help, -help, -h :              : Prints out this text.\n"
        "-dryrun, -d       : <true|false> : Overrides conf file DRYRUN setting.\n"
        "-remove, -r       : IPv4*        : Removes from master list immediately.\n"
        "-check, -c        : IPv4*        : Check IP status in list.\n"
        "-purge, -p        : #days        : Purges blocklist entries older than #days.\n"
        "-version, -v      :              : Prints the version number.\n"
        "-verbosity, -V    : level**      : Change the verbosity.\n"
        "\n"
        "Note that the dotted IPv4 address or domain name may not have a cidr.\n"
        "All commands except -help and -version must be run as root.\n"
        "\n\n"
        "*  Dotted IPv4 or domain name that can be resolved into an IPv4 address.\n"
        "** Verbosity level can be: quiet, fatal, warn, status.\n\n";
        
    if (notUsed)
    {
        printf("Unknown argument to -help\n");
        return(1);
    }
    printf("%s", HelpStr);

    return(1);
}


static int dryrun(char *valstr)
{
    P_DryRun = 1;    // defaults to true
    if (valstr && stricmp(valstr, "false") == 0) P_DryRun = 0;

    return(0);
}


static int removeIp(char *ipStr)
{
    return(ProcessParameter(ipStr, REMOVE));
}


static int check(char *ipStr)
{
    return(ProcessParameter(ipStr, CHECKIP));
}


static int purge(char *daysStr)
{
    return(ProcessParameter(daysStr, PURGE));
}


static int version(char *notUsed)
{
    if (!notUsed)
    {
        printf("%s\n%s\n", VERSION, VERSION2);
    }
    return(1);
}

static int verbosity(char *str)
{
    int i;
    char *cmds[4] = {"QUIET", "FATAL", "WARN", "STATUS" };

    P_Verbosity = STATUS;
    if (str)
    {
        for (i = 0; i < (sizeof(cmds) / sizeof(cmds[0])); i++)
        {
            if (stricmp(str, cmds[i]) == 0)
            {
                P_Verbosity = i;
                printf("Verbosity forced to %s\n", str);
                return(0);
            }
        }
        PrintErr(STATUS, "Verbosity %s is invalid.  Forced to STATUS.\n", str);
    }

    return(0);
}

// Search for command line options and process them.
// Return 0 if program should continue, or 1 if it should exit.

int ProcessCmdLine(int argc, char *argv[])
{
    /* Define the function table mapping strings to function pointers */
    static const CmdTableEntry function_table[] =
    {
        {"-help", ShowHelp},
        {"help", ShowHelp},
        {"h", ShowHelp},
        {"dryrun", dryrun},
        {"d", dryrun},
        {"remove", removeIp},
        {"r", removeIp},
        {"check", check},
        {"c", check},
        {"purge", purge},
        {"p", purge},
        {"version", version},
        {"v", version},
        {"verbosity", verbosity},
        {"V", verbosity},
        {NULL, NULL}
    };

    char *var_name;
    char *param = NULL;
    int i;

    // Guard clause: ensure there is at least one argument passed
    if (argc < 2 || argv[1] == NULL) return(0);

    var_name = argv[1];

    // Strip the leading dash if present
    if (var_name[0] == '-') var_name++;

    // Extract the parameter if it exists and does not begin with a dash
    if (argc > 2 && argv[2] != NULL && argv[2][0] != '-') param = argv[2];

    // Lookup the variable name in the function table
    for (i = 0; function_table[i].cmd_name; i++)
    {
        if (strcmp(var_name, function_table[i].cmd_name) == 0)
        {
            // Execute the matched function pointer and return its code
            return(function_table[i].func_ptr(param));
        }
    }

    /* Fallback case: variable name not found in the table */
    PrintErr(STATUS, "Error: Unknown command line option '%s'\n", argv[1]);
    PrintErr(STATUS, "\nUse: \"AutoBlock -h\" for help.\n");

    return 1;  // Return and exit
}



