
# The AutoBlock Config File

The AutoBlock Config file *AutoBlock.conf* contains several variables that need to be set according to your Asterisk configuration.  

To protect the integrity of the config file, only root can edit this file so you will need to use sudo:

>><b>sudo nano /etc/AutoBlock.conf</b>

If you don't use 'sudo' then you wont be able to save your changes.
    
## Layout

The AutoBlock.conf file is similar to the conf files used by Asterisk, but different.  Firstly, blank lines are ignored as well as anything *after* and including the '#' comment character.  This includes the backslash character.  If you use the backslash character to continue the line over to multiple lines, it must occur before any '#' comment characters or else it will be stripped away with the comment.

Variables do not have to be in any particular order.  Also, the variable names themselves are not case sensitive.  Whatever seems convenient is best.

The overall variable assignment syntax is:

VarName: parameter1, parameter2, ..., parameterN

All variables will accept multiple parameters, but not all will use more than the first.

Multiple declarations of the same variables are allowed, but only the last declaration is accepted.  There is no error given if multiple declarations exist so you need to watch out for that.  So if you have:

DryRun: TRUE  
DRYRUN: FALSE
dryRUN: TRUE        <-- Only this one counts


## Variables

Here is a list of variables that can be changed:<p>


| <br>Variable | <br>Description | Multiple<br>Parameters | <br>Default Value |
| :--- | :--- | :--- | :--- |
| `DRYRUN` | No change mode | NO | TRUE |
| `VERBOSITY` | QUIET, FATAL, WARN, STATUS | NO | STATUS |
| `LOGFILEPATH` | Path to AutoBlock.log | NO | "/var/log/AutoBlock.log" |
| `AsteriskNOTICEFILE` | Path to Asterisk log file | NO | "/var/log/Asterisk/messages.log" |
| `FIREWALLBLOCKLISTPATH` | Path on router for ipset | NO | "/mnt/usb/AutoBlock/blocklist.txt" |
| `REQUESTTYPES` | REGISTER, INVITE, OPTIONS, * | YES | * |
| `ALLOWNAMEDSERVER` | Whitelist named servers | NO | FALSE |
| `ALLOWEDNUMERICALIDS` | Permitted numerical accounts | YES | 0-4000 |
| `IGNOREBLOCKS` | Whitelisted netblocks | YES | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 |
| `MINCIDR` | Minimum CIDR bits | NO | 8 |
| `MAXCIDR` | Maximum CIDR bits | NO | 24 |
| `USEWHOIS` | Use whois to get netblock | NO | TRUE |
| `TRANSFERCMD` | Command to send to router | NO | "timeout 300 rsync -c -e 'ssh -o BatchMode=yes' %src% root@192.168.1.1:%dst%" |
| `RELOADCMD` | Command to reload firewall | NO | "ssh -o BatchMode=yes root@192.168.1.1 ' /etc/init.d/firewall reload' " |
| `IMPORT`   | Import from public list | YES | <empty\>
| `COMPRESS` | Compression Aggressiveness | NO | 51 |
| `EXPIRE`   | Days to IP Expiration | NO | -1 |

Note that all variables must be in the config file even if defaults are used.

---------

### DRYRUN
If set to TRUE, AutoBlock will process the messages file normally, but will not attempt to copy the resulting blocklist to the router.  Set this to FALSE for normal processing.  

Allowed Values: TRUE, FALSE

> **DryRun:&nbsp;&nbsp;&nbsp;&nbsp; TRUE**


----------


### LOGFILEPATH 
This is the path where the AutoBlock program writes its log files.  This is not the asterisk log file.  If this variable is a valid path, then any AutoBlock messages will be written there.  If you don't want any logging, leave this variable blank.  Only messages of WARN or higher level will be written. 

**NOTE**: Be sure to use forward slashes '/' and not backslashes '\' because the latter is treated as a line continuation.

Allowed Values: Blank or any valid path where the program has permission to create and write files.

> **LogFilePath:&nbsp;&nbsp;&nbsp;&nbsp;      "/var/log/AutoBlock.log"**

-----------


### VERBOSITY
This sets the minimum severity of messages that are displayed to the console.  Normally, console messages are discarded when the program runs as a cron job.  This is primarily for debugging your configuration, so setting it to STATUS gives more useful information.  This variable does not affect the verbosity applied to the log file.
<br>

| The parameter can be one of the following: |
| :--- |
|    QUIET  - No messages of any level. |
|    FATAL  - Severe errors that could stop the program. |
|    WARN   - Errors, but the program can continue. |
|    STATUS - Chatty messages indicating program flow. |

> **Verbosity:&nbsp;&nbsp;&nbsp;&nbsp;     STATUS**


------------



### ASTERISKNOTICEFILE
This is the path to the Asterisk log file (messages.log).  It can be in the usual location or in a custom location.  

**NOTE**: Be sure to use forward slashes ‘/’ and not backslashes ‘\’ because the latter is treated as a line continuation. 

Allowed Values: Must be a valid path to the asterisk log file and the program must have read permission.

> **AsteriskNoticeFile:   &nbsp;&nbsp;&nbsp;&nbsp;    "/var/log/asterisk/messages.log" &nbsp;&nbsp;&nbsp;&nbsp;  # default location**


-------------


### FIREWALLBLOCKLISTPATH
This variable is the path on the router where the blocklist will be copied to.  

**NOTE**: Be sure to use forward slashes ‘/’ and not backslashes ‘\’ because the latter is treated as a line continuation. 
**IMPORTANT** This variable must be defined before the TRANSFERCMD variable below.

Allowed Values: Must be a valid path on the machine it is later copied to and the program must have write 
 permission using the method of copy defined elsewhere. **Path must NOT contain spaces**
 
 
> **FirewallBlockListPath: &nbsp;&nbsp;&nbsp;&nbsp;   '/mnt/usb/AutoBlock/blocklist.txt'**


------------


### REQUESTTYPES
This is a list of the sip request types that will be processed.  Only "REGISTER", "INVITE" and "OPTIONS" are currently supported.  Normally, you will want to process all of them, but you can omit some if you need to for special cases.  You can also just use a wildcard "*" to indicate that all known request types should be processed.  Multiple request types must be separated by a comma and optional spaces.

Allowed Values: Either "*" by itself or one or more of "REGISTER", "INVITE" and/or "OPTIONS" separated by commas and optional spaces.

> **RequestTypes:  &nbsp;&nbsp;&nbsp;&nbsp; register, options   &nbsp;&nbsp;&nbsp;&nbsp;  // Omit INVITE processing**<br>
> **RequestTypes:  &nbsp;&nbsp;&nbsp;&nbsp; *                 &nbsp;&nbsp;&nbsp;&nbsp;     // process all known requests**


-----------



### ALLOWNAMEDSERVER
If set TRUE, will cause the program to ignore error messages if the user has connected to your server by name (e.g.- "Myserver.com") as opposed to an IP address.  In most cases, but not all, attackers will connect to your server by its IP address, whereas legitimate users will use your domain name.  

It is safest to set this value to FALSE which will process all errors equally.  A positive integer can also be used which would be the same as TRUE, but only until that count was reached.  So if the count is 50, then the first 50 errors are ignored, but the 51st error will be processed.  If a count is used, then the number should be sufficiently large to prevent a legitimate user with a misconfigured ATA from being accidentally blocked.  The counts are reset every time the program is run and are not IP specific.

Allowed Values: "True", "False" or a positive integer less than 100,000.

> **AllowNamedServer:  &nbsp;&nbsp;&nbsp;&nbsp; false**


--------------



### ALLOWEDNUMERICALIDS
If the user accounts on your Asterisk server are numerical (4001, 4002, etc.), and not alphanumeric (alice, fred, joe, etc.), then this variable is used to indicate the allowed valid numerical range.  This is for numerical account numbers only.  If you have any numerical user id's, they should be listed here as a range.

If you don't have any numerical user account names, and only have alphanumeric account names then leave this blank.  If the attacker attempts to register using a numerical account not in this list, he gets added to the block list.  Don't add numbers here that are not actual login id's.

Allowed Values: Positive integers and integer ranges (4000-5000).  If you have more than one range, you can include them all by separating them with a comma and optional space.  For integer ranges, the lower number must be defined first.

> **AllowedNumericalIds:  &nbsp;&nbsp;&nbsp;&nbsp;  0, 4000-5000, 9999** 



--------------




### IGNOREBLOCKS
This is a white list.  You should set this to your local IP address range plus any external users with stable IP addresses.  IP ranges must be specified as a CIDR block and not as a hyphenated range.  

Connections from an IP address listed here will always be allowed in, regardless of prior blocks.  So if the IP is banned by a public block list, then listing it here will allow it to connect to your Asterisk server unimpeded.  

This variable supports single IPs (12.23.34.45), IPs/cidr (50.100.0.0/16) , domains (mydomain.org), and domains/cidr (mydomain.org/24).  Whitelisting domains is useful when a valid user has a dynamic IP address and also a DDNS provider.  AutoBlock resolves the DDNS domain IP for each run so if it changes, it is white listed with the new IP address.

NOTE: You can use a '\' if you need more than one line.  
 
Allowed Values: Dotted IP addresses and domain names, with or without a "/" netblock size, all separated by commas and optional spaces.

> **IgnoreBlocks:  &nbsp;&nbsp;&nbsp;&nbsp; 192.168.1.0/24,  users.ddns.domain.com/24**<br>
> **IgnoreBlocks:  &nbsp;&nbsp;&nbsp;&nbsp; 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16**


------------------


### MINCIDR 
This is the minimum allowable number of cidr netblock bits.  The lower this number, the more IP's are blocked.  This forces the cidr to be no smaller than this value regardless of the value returned by WHOIS.  

Allowed Values: A positive integer < 32 and must not be >= MaxCidr below.

> **MinCidr:  &nbsp;&nbsp;&nbsp;&nbsp; 8**


-------------


### MAXCIDR 
This is the maximum allowable number of cidr netblock bits.  The higher this number, the fewer IPs are blocked.  It is best to use a value like 24 to ensure that at least a minimum sized netblock is added to the block list.  Note that if MinCidr and MaxCidr are equal or overlap, unpredictable results may occur and the program may crash.

Allowed Values: A positive integer > MinCidr above and <= 32.

> **MaxCidr:  &nbsp;&nbsp;&nbsp;&nbsp; 24**



-------------


### USEWHOIS
When set to TRUE, this causes the program to ask WHOIS what the official netblock size is.  Whois is only called for IPs that have been found in your Asterisk log and never imported IPs.  Normally you want to set this to TRUE in order to block all IP's that a public VPN might be using.  If you have a huge number of "unique" IP addresses that need to be blocked, sometimes this will delay processing since each WHOIS lookup takes one second due to whois restrictions.  This is because if you try to hit the WHOIS server any faster, it can result in YOUR server being treated as an attacker and blocked.  If you set this variable to FALSE, then WHOIS will not be contacted and the IP netblock size will be set to the value of MaxCidr above.  This will save you one second for each "Unique" IP added but at the risk of letting hackers that use VPN's to have continued access to your server.  NOTE that whois is only contacted for NEW IPs that have been found in the Asterisk log file.  So depending on the cron frequency, leaving this active will rarely add more than a minute to each run.

Allowed Values: "True" or "false"

> **UseWhois:  &nbsp;&nbsp;&nbsp;&nbsp; true**



-------------


### TRANSFERCMD
This is the Linux command that will send the ipset file to the router or firewall.  The macros %dst% and %src% may be used to simplify the command.  The %dst% macro is replaced with the path to the ipset on the router.  This is set with the FIREWALLBLOCKLISTPATH variable above.  The %src% macro is replaced with a local path to the local ipset.

**IMPORTANT**: FIREWALLBLOCKLISTPATH must be defined before this variable.

The following examples may be used:

* "rsync -c -e 'ssh -o BatchMode=yes' %src% root@openwrt.lan:%dst%"    
* "scp -O -o BatchMode=yes %src% root@192.168.1.1:%dst%"
* "cp %src% %dst%"      // Recommended only if using the firewall on the asterisk machine.

PLEASE TEST THESE COMMANDS MANUALLY BEFORE INCLUDING THEM HERE.  Make sure that ssh works with keys so no password is required. Make sure you use the proper IP address or local domain name of your router.  Below you will notice the use of "timeout".  This force closes the program if it takes more than 300 seconds (5 minutes).

> **TransferCmd: &nbsp;&nbsp;&nbsp;&nbsp; "timeout 300 rsync -c  -e 'ssh -o BatchMode=yes' %src% root@192.168.1.1:%dst%"**



--------------------


### RELOADCMD
This is the command that will reload the firewall after the ipset has been transferred. This can be any valid Linux command.

> **ReloadCmd:&nbsp;&nbsp;&nbsp;&nbsp; "ssh -o BatchMode=yes root@192.168.1.1 ' /etc/init.d/firewall reload' "**


------------


### IMPORT
There are several publicly posted IP sets online that you can add to your own blacklist.  In order for the parser to include them properly, they must have only one IP on each line with no characters except numbers, dots and an optional '/'.  Only IPv4 is supported.  The import variable parameters may be a valid url or a valid path to a local file.  If you find an Ipset in a different format, then you need to write your own script to read it and write a file in the proper format, then include the file path here.  To include more than one list, separate with commas and use backslash characters to continue the line.

> **Import:&nbsp;&nbsp;&nbsp;&nbsp; "https://raw.githubusercontent.com/sgofferj/sipblocklist/refs/heads/master/sipblocklist.zone"** , \ <br>
>    **&nbsp;&nbsp;&nbsp;&nbsp;      "https://www.voipbl.org/update"**

> **Import:  &nbsp;&nbsp;&nbsp;&nbsp;  "/var/tmp/TmpImport.txt"**


---------------


### COMPRESS
To keep the IP address list small, a compression algorithm groups nearby IPs into blocks.  This variable sets the threshold for grouping: it defines the percentage of IPs that must be present in a range before the system merges them into a single CIDR block.  Set to 100 if no compression is wanted.  Optimal values seem to be between 51 and 75.

> **Compress:&nbsp;&nbsp;&nbsp;&nbsp; 51**


-----------------

### EXPIRE
This is the number of days before an IP address expires.  Use -1 if you don't want them to expire.

> **EXPIRE: &nbsp;&nbsp;&nbsp;&nbsp; 30**





