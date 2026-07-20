

# <center>INSTALLING AUTOBLOCK</center>

AutoBlock is fairly easy to install, but the configuration of the OpenWrt router itself can be a bit intimidating.  Still, for standard installations, complete installation can be done in three macro steps:

* Prepare the OpenWrt Router
* Run the AutoBlock Installation Script
* Perform a final configuration of the OpenWrt Router

Before beginning installation, please check to make sure you have met all the dependencies below.

## DEPENDENCIES 

* Asterisk Version: This program requires a fairly modern version of Asterisk that runs *`chan_pjsip`* and produces **`NOTICE`** messages that carry enough information that the attacker can be identified. AutoBlock specifically requires the following format for a `NOTICE` line:

>>[Jun 12 10:25:27] NOTICE[88448] res_pjsip/pjsip_distributor.c: Request 'INVITE' from
>>  '"'1001'" <sip:1001@1.2.3.4>' failed for '5.135.173.212:16071' (callid: 9c2726618f71e1aa-call)
>>  - No matching endpoint found

>The "failed for" is the hackers IP address. Older chan_sip installations will probably not work right.

* Router Firmware: AutoBlock requires a fairly new version of OpenWrt to be installed on your router.  Obviously, your router must also be compatible with OpenWrt firmware.  Not all are.  It is possible to use other firmware, like Merlin, DD-WRT, pfSense, etc., but this installation only covers OpenWrt.  Whatever router and firmware you use, it must support ipsets, ssh (via ssh keys), scp and rsync.

* USB Port: Your router must have a working USB port.  This is where the blocklist is stored.  If your router does not have a USB port, an alternate configuration is possible.  See the "Alternate Configurations" section.

* RAM: Your router must have adequate RAM and FLASH to handle the IpSets and load the necessary packages.  Larger datasets are more accurate, but trimming is sometimes warranted if the router memory dictates it.

* USB FLASH Drive: Because of frequent updates, the blocklist must be stored on an external flash drive.  The ideal range of capacities (sizes) is between about 8 MB and 256 MB.  Note that is MB not GB.  An older 256 MB drive is perfect.  Anything bigger than that is a waste, but is still acceptable if the router supports it.

* Linux Machine:  A linux machine other than your OpenWrt router, is required to reformat your USB FLASH Drive into ext4 format.

## Prepare the OpenWrt Router

Before starting the actual installation of AutoBlock on your Asterisk server, there are two things in the router we need to take care of first:

* Make sure SSH is working.
* Set up the external USB drive.

## 1. Configure SSH

A. Log in to your OpenWrt web GUI.
b. Go to **System ➔ Administration** and then click the **SSH access** tab. 
c. Make sure **Interface** is set to **LAN only**. <br>
(Never enable WAN mode or everyone on the Internet will have access to your router and possibly be able to change things.  Even with the most complicated password in the world, an OpenWrt router is vulnerable if exposed to the Internet.  If you haven't changed your password from the default, change the word *vulnerable* in the preceding sentence to *compromised*.)
d. Port should be 22. 
e. Check to allow **Password Authentication** and **Allow Root Passwords**. 
f. Click Save and Apply. 

Note that the AutoBlock installation script requires ssh to work with passwords, but after it is installed, you may disable password authentication if you wish. AutoBlock itself only uses ssh keys for authentication once it is installed.  

If the AutoBlock installer has a problem setting up the keys for ssh, then manual entry of the keys may be required under the **SSH keys** tab, but for now, just leave those alone.

## 2. Configure External USB FLASH Drive

### A. Prepare the USB FLASH Drive Itself:
1. Plug your USB FLASH Drive into a Linux machine, other than your OpenWrt Router, preferably a desktop machine.  
2. Using the other linux machine, perform the following tasks:
    * Read and understand the instructions for your drive partition editor.
    * If the USB FLASH Drive is already formatted as EXT4, then skip to formatting.
    * Change the partition format to ext4.  Use MBR if the drive is less than 2 TB.
    * Format the drive.
    * **This will destroy all data that is currently on the flash drive.  AND** if you did something incorrectly, it could erase  all the data from your desktop drive.  **SO use your partitioning program with extreme caution!!!**

### B. Tell OpenWrt to Mount the New Drive
1. Insert the ext4 partitioned flash drive into the router.
2. In the OpenWrt GUI, go to **System ➔ Software**. 
3. Click the "Update Lists" button and wait for it to complete. 
4. In the filter box, type each of the following package names one by one and install them if they are not already installed.
    * rsync
    * block-mount 
    * kmod-usb-storage 
    * kmod-usb-storage-uas 
    * kmod-fs-ext4 e2fsprogs 
5. REBOOT the Router.
6. When the router comes back up, go to System ➔ Mount Points.  If it is not there, then you need to find out why before continuing.
7. Scroll down to the Mount Points section at the bottom.
8. Look for your USB partition in the list (it will likely be listed as /dev/sda1).
9. Click the Edit button on the right side of your USB partition row.  In the configuration window that opens:
    * Check the box next to Enabled.
    * In the Mount point dropdown or text box, select: **/mnt/usb**  If it is not selectable, select *custom* and enter it manually.
10. Click Save at the bottom of that window.
11. Click the green Save & Apply button at the bottom right of the main page.

Your USB drive should now be mounted permanently to **/mnt/usb** . Reboot your router now to make sure that the mounting will survive a reboot.
        

## Run the AutoBlock Installation Script

1. Use ssh or the direct console to log into your asterisk server.  
2. Make sure you have the most current package library.  Run ***sudo apt update*** (Note the package manager instructions are for debian based systems.)
3. If using a direct console to access your asterisk server, make sure that ssh in installed.  Run ***ssh -V*** at the command line,  If ssh is installed, it should report back with the version number.  On nearly all debian based linux machines, ssh is already installed.  If it is not installed, run ***sudo apt install openssh-client -y*** . 
4. You will also need to have curl installed on your asterisk machine.  Most likely, it is already there, but run ***sudo apt install curl -y*** to be sure.
5. Download the AutoBlock installation script to your asterisk machine with the following commands:

    > <strong>cd ~</strong><br><strong>curl -fsSL -O https://github.com/n4mwd/AutoBlock/raw/refs/heads/main/Install-AutoBlock.sh</strong>

6. Next, run the install script. This script requires root access in order to set everything up to run as root. Both the install script and the AutoBlock program itself must be run as root. The install script will stop and ask before doing anything important. Run the command below. Because this uses sudo, it might ask you for your root password for the Asterisk server.

    > <strong>sudo bash Install-AutoBlock.sh</strong>
    
    


## Perform a final configuration of the OpenWrt Router

### 1. Configure the Firewall for IpSets

a. Log in to the OpenWrt GUI and Select **Network -> FireWall**.
b. Click the **IpSets** tab. 
c. Click **Add**. 
d. Enter the following:

    * **Name**: "IncludedIpSet"
    * **Comment**: "Automatically generated by Asterisk"
    * **Packet Field Match**: "net: (sub)net"
    * **IPs/Networks, MACs**: leave blank
    * **MaxEntries**: leave blank
    * **Include File**: Click the "SELECT FILE" button, then the "AutoBlock" folder, and then select "blocklist.txt".
    * **timeout**: 0
    * **counters**: check for now, it lets to see how many packets have been blocked. It gets reset to zero every time AutoBlock is run.  Uncheck after you have AutoBlock working properly.

f. Click **Save** to close page, then **Save & Apply** on the following page.

## 2. Configure Firewall to Block your IpSet

a. Now go to **Network -> Firewall** and click the **Traffic Rules** tab. 
b. Click **ADD** and then the **General Settings** tab. 
c. Enter the following fields:

    * **Name**: "Block-Attacker-IPSet"
    * **Protocol**: UDP
    * **Source zone**: WAN
    * **Source Address**: leave blank
    * **Source Port**: Leave default
    * **Destination zone**: ANY
    * **Destination Address**: leave blank
    * **Destination Port**: leave default
    * **Action**: DROP

d. Click the **Advanced Settings** Tab and set the fields to the following:

    * **Match Device**: Unspecified
    * **Restrict to address family**: IPv4 only
    * **Use IPset**: Use the drop down to select "IncludedIPSet"
    * The remaining fields can be left set to their defaults.

e. Click **Save** to close page, then **Save & Apply** on the following page.

If you made the above changes correctly, the router is ready to work with AutoBlock. If the changes seem to make your router unstable, un-check the enable box for the "Block Attacker Rule" until you can figure what went wrong. OpenWrt can get finicky sometimes. Usually, a reboot followed by a power cycle will fix things.



## Alternate Configurations

The use of alternate configurations are not officially supported, but the following can give you some ideas on how to configure the system.

* Non-OpenWrt routers: If you can log in to the router with ssh, and it supports IpSets, then it is possible to use it, however, the directories will likely be in different locations.  You'll need to be able to provide AutoBlock.conf with the location to upload the blocklist.txt file and also the command to restart the filewall.  The router must also be configured to use IpSets.

* Using the Asterisk Firewall: If the router issue cannot be overcome, then it is possible to use the firewall on the asterisk server itself.  In AutoBlock.conf, the command to copy the file would likely be a "cp" rather than a rsync command.  The command to restart the firewall should also be local.  Bear in mind that some container managers do not give you access to the firewall, but you should have no problem if running on bare metal or in a QEMU virtual machine.

* USB FLASH Drive: If you configure AutoBlock to continuously write the blocklist file to the router's flash memory, the router would wear out in only a few months.  To fix this, we use an external USB FLASH Drive which usually have wear leveling which will last for years. Unfortunately, not all routers have USB sockets which means something else has to be done.  Two possible options are:
  1. RAM Drive:  The blocklist can be stored on a RAM drive instead.  This may sound ideal at first, but when you realize that the blocklist is gone after a reboot, you will find out that your asterisk server is completely unprotected.  If using a RAM drive, you need to make a router startup script to copy the file directly from the asterisk server.  This will work if your blocklist doesn't exceed the size of your RAM drive.  The blocklist can easily get over 1 MB in size.
  2. If a RAM drive isn't feasible, the next best option is use the firewall in the Asterisk server.  Unfortunately, this is not always an option if you are running Asterisk inside certain containers.  If you are in that boat, the a RAM drive makes more sense.  You can keep the blocklist file smaller by not importing any public blocklists.  If it gets too big, you can delete the /root/AutoBlock/whois.txt file which will delete all the accumulated IPs.
  
* Intermediate Router: If the main router cannot be used, it is possible to configure a second router with OpenWrt firmware that sits between your main router and your Asterisk server.  The second router must have NAT (Masquerading) disabled and be configured to pass all traffic except for that which is blocked by the IpSet.

* Everything Runs On The Router: It is possible, but not recommended, to run everything on the router.  In this configuration, the OpenWrt firmware also runs Asterisk and AutoBlock.  For this to work, you will need a fairly beefy router with plenty of RAM and FLASH.  This could work for home users and small businesses where VOIP traffic and internet usage is minimal.  The down side is that you might not have enough CPU cycles available to perform all of the tasks that need to be done.  Also, if your router stops working, then Asterisk also stops working.

 
 
