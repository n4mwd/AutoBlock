 
# <center>AutoBlock</center>

AutoBlock is an ultra-lightweight (< 50K) Asterisk intrusion prevention system that stops hackers at your router before they ever touch your Asterisk server. A fast, low cpu resource alternative to *Fail2Ban*, it intelligently analyzes standard Asterisk logs for malicious activity and then automatically sends a list of hacker IP netblocks to your OpenWrt router.  It aggressively neutralizes entire hacker netblocks rather than just single IP addresses. This proactive approach permanently cuts off attackers that attempt to mask themselves using public VPNs. 

AutoBlock runs as a cron job and searches for hackers using the Asterisk `NOTICE` message and **DOES NOT** use the excessively voluminous `SECURITY` messages. So using the `SECURITY` flag for logging is not required and strongly discouraged.

AutoBlock operates with maximum efficiency, low system overhead, and zero reliance on bloated security logs.  In addition, AutoBlock can seamlessly include publicly available VOIP hacker lists so most hackers never get a chance to make a log entry in the first place.

If you are familiar with <u>*Fail2Ban*</u>, then you already understand the basic principles of AutoBlock.  There are advantages and disadvantages to both.  Fail2Ban is generally for larger systems with CPU and disk resources to spare, whereas AutoBlock is designed for smaller systems.  AutoBlock runs fine on a Raspberry Pi 3b with only 1 Gb of RAM.  Running Fail2Ban on a Pi 3b would choke the system when continuously parsing SECURITY logs.

Here is a comparison bewteen Fail2Ban and AutoBlock:  <br>


| Feature | Fail2Ban | AutoBlock |
|---|---|---|
| System Footprint | Heavy (Python-based daemon) | Ultra-lightweight (< 50K binary) |
| Written Language | Slow Interpreted Python | Fast&amp;Lean Compiled C |
| Target Scope | Any service (SSH, Web, Asterisk) | Asterisk Only |
| Blocking Scope | Single IP addresses (/32) | Entire ISP/VPN Netblocks (/16 or /24) |
| Defense Location | Locally on the server | Offloaded to Router |
| Log Dependency | High-volume SECURITY logging | Minimal NOTICE logging |
| Processing Frequency | Continuous | Batch (every 15 min to 1 day) |
| Support | Massive Community | Brand New |
| Ban Length | Temporary and Permanent | Temporary only |
| Whitelist DDNS | Not Supported | Supported (Incl. DDNS Netblocks) |
| Real Time Notification | Supported | Not Supported |
| Public Blacklists | Not Supported | Supported |
| IP Family | IPv4 and IPv6 | IPv4 Only |


## What AutoBlock Does

AutoBlock protects your Asterisk server from brute-force attacks while safeguarding your hardware and blocking hackers permanently at the router.

### 1. Prevents Hardware Damage
Brute-force attacks generate millions of failed login attempts. This flood of data overwrites logs constantly, which can cause physical wear and premature failure on solid-state drives (SSDs).

### 2. Blocks Entire Netblocks, Not Just Single IPs

Instead of blocking a single IP address, AutoBlock identifies the entity owning that IP and blocks their entire netblock.

* Example: A hacker attacking from 5.135.64.122 triggers an ownership rule that blocks all of 5.135.0.0/16.
* Result: A single entry instantly bans 65,536 IP addresses. This stops hackers from simply switching to a different IP address provided by their public VPN.

### 3. Stops Attacks at the Router Perimeter

Once compiled, AutoBlock uploads the blocklist directly to your OpenWrt router. This ensures malicious traffic is dropped at the edge of your network before it ever reaches your Asterisk server.

(Note: While it is possible to use the ipset compatible firewall in your Asterisk server and not use an OpenWrt router, that setup is not covered in this guide).

## What if one of my remote users accidentally gets added to the block list?

AutoBlock fully supports a whitelist.  You can add your user's IP addresses or you can use a domain name.  If your user still manages to get added to the block list, you can manually remove his IP with: 

```
    sudo AutoBlock -remove <IP or url>
```

## AutoBlock Limitations

* Asterisk Version: AutoBlock will not work with older versions of Asterisk that do not give sufficient information in a NOTICE log entry.  Older versions would tell you that someone was attacking, but not who was doing it.  See the Dependencies section below for the NOTICE format required.  Generally, the use of chan_pjsip is required over chan_sip.
* OS Dependent: AutoBlock was designed to run on Debian based Linux machines (Ubuntu, MX Linux, etc).  However, it is distributed as source so it very possible, but not guaranteed, to work on non-Debian Linux Distros (Red Hat, Arch, etc.).  It can even be compiled to run under windows if you could get Asterisk to run on Windows.
* IPv4 Only: AutoBlock does not support IPv6.  It is recommended that IPv6 access to your Asterisk server be turned off.  Even if IPv6 was supported, the IPv6 address space is so vast that blocking all the bad guys would be impractical.  A typical home user account could have trillions upon trillions of IPv6 addresses to choose from when hacking other people's servers.
* Router Dependency: AutoBlock was developed to have a symbiotic relationship with an OpenWrt router.  The default commands in AutoBlock.conf usually work perfectly with modern OpenWrt routers.  For routers running firmware other than OpenWrt, if they support remote access with ssh, scp and rsync, then  modifying the AutoBlock.conf file is usually all that is required.  Routers that do not support remote access with ssh cannot be used.  It is possible to bypass the router requirement by using the firewall on the Asterisk server itself, but that method is not officially supported.




## Will my Public VPN get blocked by AutoBlock?

Yes, your Public VPN could get blocked under certain conditions. AutoBlock automatically stops all blacklisted incoming UDP traffic at the router level. Because many VPNs rely on the UDP protocol, this can disrupt your connection.

Here is how AutoBlock impacts different VPN setups:

* Remote Access via Public VPN: If you use a public UDP-based VPN to connect to your Asterisk server from off-site, AutoBlock will likely block it eventually since hackers use the same public VPNs.
* Local Use of Public VPN: If you use a public UDP-based VPN on your local network to browse external websites, your connection is less likely, but still possible, to face disruption.  If your public VPN uses a symmetric UDP port to transfer data, it will not likely have any issues.  Likewise, if it uses a TCP port, it will not be affected.

If you experience connectivity issues accessing your public VPN, you can resolve them using two main methods:

* Switch to TCP Mode: Change your public VPN provider's connection settings from UDP to TCP mode to bypass the filter.
* Create a Private VPN: Configure OpenWrt to run a private WireGuard VPN. This completely eliminates the blocking problem. While this method does not provide anonymity, it does protect your data when operating remotely.  It also has the advantage of being able to access other computers and printers from off site in a totally secure way.


## What Happens If You Aren't using An OpenWrt Router?

You can use other routers, but AutoBlock requires the router to be remotely accessible with ssh using ssh keys. It also requires that whatever firewall is being used by the router, it must be compatible with IpSets. Most newer versions of OpenWrt support IpSets. Non-standard installations, where the firewall on the Asterisk server itself is being used to block the IPs, can be used but are not officially supported.



        
    
## AUTOBLOCK INSTALLATION

Installing AutoBlock is done in three macro steps:

* Prepare the Router
* Run the AutoBlock Installation Script
* Finish Configuring the Router

[For Detailed Instructions Click Here](installation.md)




## TESTING

The config file has a parameter called `DryRun` that is set to true as a default. This goes through all the motions, but does not perform the final copy to the router. Leave `DryRun` set to true until you are certain the program is configured correctly.

To run the program outside of cron, enter the following on the command line:

>**AutoBlock**



The default verbosity is set to `STATUS` which will print numerous diagnostic messages on the screen indicating if everything went OK.

## AUTOBLOCK CONFIGURATION

The AutoBlock configuration file is located in /etc/AutoBlock.conf.  It must be edited by the root user.  Most of the file is self explanatory, but for more detailed explanations of the variables, [CLICK HERE](ConfigSetup.md)


## Asterisk CONFIGURATION

On your Asterisk machine, the logger must be active and you should have a line similar to the following in your `/etc/Asterisk/logger.conf` file:

```text
    messages.log => notice,warning,error

```

The name of the log file here that Asterisk will generate is "messages.log" and this should match the config variable `AsteriskNOTICEFILE`. Also, since AutoBlock only looks at `NOTICE` log messages, the word "notice" must appear as shown in the above line. You should not include "security" here or else Asterisk will continuously spew an extremely high volume of status messages, most of them useless, to your log file. The security flag is not used by AutoBlock and, if included, will cause more harm than good.

## RUNNING AUTOBLOCK

If everything went like it should, Cron should be automatically running AutoBlock at the frequency you selected in the install file. If something doesn't seem like its working quite right, then you can look in the `/var/log/AutoBlock.log` file for clues. As said before, you can run AutoBlock manually by simply entering "AutoBlock" on the command line. 


### COMMAND LINE OPTIONS

Only one command line option with an optional parameter is allowed at a time.  The following is a list of command line options that might be useful.


| OPTION | PARAMETER | DESCRIPTION |
| :--- | :--- | :--- |
|--help, -help, -h | `<empty>` | Prints out helpful information. |
| -dryrun, -d | `<empty>`, true, false | Overrides conf file DRYRUN setting.  Default=true. |
| -remove, -r | IPv4`*` | Removes IP from whois list immediately.  |
| -check, -c | IPv4`*`  | Check to see if the IP is in the whois list. |
| -purge, -p | #days |  Purges whois entries older than #days |
| -version, -v  | `<empty>` | Prints the version number. |
| -verbosity, -V | level`**` | Overrides conf file VERBOSITY |

`*` Can be either a dotted IPv4 address (no cidr) or a domain name that will resolve to an IPv4 address.<br>
`**` Verbosity level can be: quiet, fatal, warn, status.
