#!/bin/bash

# ==============================================================================
# Script Name: install-AutoBlock.sh
# Purpose: All-in-one interactive installation, compilation, network audit, 
#          and cron scheduling suite for the AutoBlock system.
# ==============================================================================

GITHUB_USER="YOUR_GITHUB_USERNAME"
GITHUB_REPO="YOUR_REPO_NAME"
BRANCH="main"

TARGET_DIR="/usr/AutoBlock"
TARBALL_URL="https://github.com/n4mwd/AutoBlock/archive/refs/heads/main.tar.gz"

# ------------------------------------------------------------------------------
# UNIFIED PROMPT FUNCTION
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# UNIFIED PROMPT FUNCTION (Strict Input Validation)
# ------------------------------------------------------------------------------
prompt_user() 
{
    local message="$1"
    echo ""
    echo "------------------------------------------------------------------"
    echo -e "$message"
    echo "------------------------------------------------------------------"
    
    while true; do
        local choice
        # -s hides the keystroke if you don't want random characters showing up,
        # but leaving it off lets them see what they typed.
        read -r -n 1 -p "Press [ENTER] to continue, or 'q' to abort script: " choice
        
        # Check if the user pressed ENTER. 
        # In a single-character read (-n 1), pressing ENTER results in an empty variable.
        if [ -z "$choice" ]; then
            echo "" # Newline for clean spacing
            break   # Exit the loop and continue with installation
        fi

        # Check if the user pressed q or Q
        if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
            echo -e "\nInstallation safely aborted by user."
            exit 0
        fi

        # If they pressed anything else, the loop repeats
        echo -e "\nInvalid key pressed. Please use [ENTER] or [q]."
    done
}

# 1. Package Manager Identification Helper Function
# Returns: 0 = Unknown, 1 = apt, 2 = dnf, 3 = yum, 4 = apk, 5 = pacman
get_package_manager_id() 
{
    if command -v apt-get >/dev/null 2>&1;  then echo 1
    elif command -v dnf >/dev/null 2>&1;    then echo 2
    elif command -v yum >/dev/null 2>&1;    then echo 3
    elif command -v apk >/dev/null 2>&1;    then echo 4
    elif command -v pacman >/dev/null 2>&1; then echo 5
    else                                         echo 0
    fi
}

# 2. Main Dependency Guard Function
check_and_install_dependencies() 
{
    local sys_id
    sys_id=$(get_package_manager_id)

    # Base commands aligned to match sys_id index directly (leaving index 0 empty)
    local BASE_CMD_ARRAY=(
        ""
        "apt-get update && apt-get install -y"
        "dnf install -y"
        "yum install -y"
        "apk update && apk add"
        "pacman -Sy --noconfirm"
    )
    local base_cmd="${BASE_CMD_ARRAY[$sys_id]}"
    

    # Core arrays aligned strictly by index
    # Index position:       0=gcc            1=curl   2=rsync  3=ssh             4=ip         5=ping           6=nc
    local REQ_BINARIES=(    "gcc"            "curl"   "rsync"  "ssh"             "ip"         "ping"           "nc")
    local NULL_PACKAGES=("${REQ_BINARIES[@]}")  # copy
    local APT_PACKAGES=(    "build-essential" "curl"   "rsync"  "openssh-client"  "iproute2"   "iputils-ping"   "netcat-openbsd")
    local DNF_PACKAGES=(    "gcc gcc-c++"     "curl"   "rsync"  "openssh-clients" "iproute"    "iputils"        "nc")
    local APK_PACKAGES=(    "build-base"      "curl"   "rsync"  "openssh-client"  "iproute2"   "iputils-ping"   "netcat-openbsd")
    local PACMAN_PACKAGES=( "base-devel"      "curl"   "rsync"  "openssh"         "iproute2"   "iputils"        "gnu-netcat")

    # Establish nameref pointer to the target system's package array
    case "$sys_id" in
        0) declare -n pkg_map=NULL_PACKAGES ;;   # unknown package manager
        1) declare -n pkg_map=APT_PACKAGES ;; 
        2|3) declare -n pkg_map=DNF_PACKAGES ;; # Yum and DNF share identical package structures
        4) declare -n pkg_map=APK_PACKAGES ;;
        5) declare -n pkg_map=PACMAN_PACKAGES ;;
    esac

    # Scan for missing binaries and gather package names into an array
    local to_install=()
    for idx in "${!REQ_BINARIES[@]}"; do
        if ! command -v "${REQ_BINARIES[$idx]}" >/dev/null 2>&1; then
            to_install+=("${pkg_map[$idx]}")
        fi
    done

    # If all binaries are present, exit the function cleanly
    if [ ${#to_install[@]} -eq 0 ]; then
        echo "All system dependencies are met."
        return 0
    fi

    # Convert the array directly to a space-separated string (no sorting/deduplication needed)
    local package_string="${to_install[*]}"

    # Output the interactive menu
    echo "================================================================="
    echo "The following packages need to be installed:"
    echo "  $package_string"
    
    # Handle the unknown package manager cleanly here
    if [ "$sys_id" -eq 0 ]; then
        echo "================================================================="
        echo "ERROR: Unsupported package manager detected."
        echo "This script cannot install these packages automatically."  
        echo "Please install them manually and run this script again."
        echo "================================================================="
        exit 1
    fi 
    
    echo "================================================================="
    echo "To install them manually, run:"
    echo "  $base_cmd $package_string"
    echo "================================================================="
    echo ""

    prompt_user "Press ENTER to install them automatically now, or press 'q' to exit: "
    
    echo "Running system installation..."
    eval "$base_cmd $package_string"

    if [ $? -ne 0 ]; then
        echo "ERROR: The package manager failed to load all of the required packages."
        echo "       Please check your network connection and try the script again."
        exit 0
    fi

    echo "All dependencies resolved successfully."
    return 0
}


Compile_Code()
{
    echo ""
    prompt_user "AutoBlock is ready to be downloaded and compiled."


    # ------------------------------------------------------------------------------
    # GIHUB REPOSITORY TARBALL DOWNLOAD
    # ------------------------------------------------------------------------------
    echo ""
    echo "Downloading AutoBlock source components from GitHub..."
    mkdir -p "$TARGET_DIR"    # make parent directories as needed

    # 1. Download the file using -L and save it into your directory
    if ! curl -fsSL "$TARBALL_URL" -o "$TARGET_DIR/main.tar.gz"; then
        echo "ERROR: Failed to download distribution components."
        exit 1
    fi
    
    # 2. Extract the archive by pointing -f to the actual file path, and -C to the directory path
    if ! tar -xzf "$TARGET_DIR/main.tar.gz" -C "$TARGET_DIR" --strip-components=1; then
        echo "ERROR: Failed to extract distribution components."
        exit 1
    fi
    
    echo "✅ Source files successfully downloaded."

    # ------------------------------------------------------------------------------
    # SOURCE COMPILATION LAYER
    # ------------------------------------------------------------------------------
    echo "Compiling AutoBlock ..."
    
    # Change into download directory
    if ! cd "$TARGET_DIR"; then
        # If here, then the cd didn't work.
        echo "================================================================="
        echo "ERROR: Could not access the $TARGET_DIR directory:"
        echo "================================================================="
    
        # Proactively check why it failed to give a smart tip
        if [ ! -d "$TARGET_DIR" ]; then
            echo "Reason: The directory does not exist."
        elif [ ! -r "$TARGET_DIR" ] || [ ! -x "$TARGET_DIR" ]; then
            echo "Reason: Permission denied."
        fi
        echo "================================================================="
        exit 1
    fi


    # Ensure we aren't using stale code from a previous run
    rm -f AutoBlock

    # Execute explicit compilation chain in local working directory
    gcc -o AutoBlock AutoBlock.c Hash-ip.c ReadIpList.c ReadMsgs.c tries.c whois.c config.c

    if [ $? -ne 0 ] || [ ! -f "AutoBlock" ]; then
        echo "❌ ERROR: Compilation failed. Cannot continue."
        exit 1
    fi
    echo "✅ Compilation successful. Program binary created."
}


#!/bin/bash

is_dropbear() 
{
    # Grab the SSH software version string via netcat
    # Dropbear banners look like: "SSH-2.0-dropbear_2022.82"
    local banner
    banner=$(nc -w 2 "$ROUTER_IP" 22 2>/dev/null | head -n 1)

    if echo "$banner" | grep -iq "dropbear"; then
        return 0 # True: It is Dropbear
    else
        return 1 # False: OpenSSH or something else
    fi
}


#!/bin/bash

# Ensure this script is running as root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run this script as root or using sudo."
    exit 1
fi

# Global Variable
ROUTER_IP="192.168.1.1" # The script assumes this is set globally

is_dropbear() 
{
    local banner
    # Quoted global variable to handle empty values safely
    banner=$(nc -w 2 "$ROUTER_IP" 22 2>/dev/null | head -n 1)

    if echo "$banner" | grep -iq "dropbear"; then
        return 0 
    else
        return 1 
    fi
}

copy_ssh_key() 
{
    # Dynamically branches using your updated global-variable function
    if is_dropbear; then
        echo "🎯 Detected Dropbear SSH server (OpenWrt/Embedded)."
        TARGET_DIR="/etc/dropbear"
        TARGET_FILE="/etc/dropbear/authorized_keys"
    else
        echo "🐧 Detected standard SSH server (OpenSSH/Generic Linux)."
        TARGET_DIR="/root/.ssh"
        TARGET_FILE="/root/.ssh/authorized_keys"
    fi

    echo "Pushing SSH key to $TARGET_FILE..."
    
    # Explicit path works perfectly since the script is fully running as root
    cat /root/.ssh/id_ed25519.pub | ssh root@"$ROUTER_IP" \
        "mkdir -p $TARGET_DIR && cat >> $TARGET_FILE && chmod 0600 $TARGET_FILE"

    if [ $? -eq 0 ]; then
        echo "✅ Operation completed successfully."
        return 0
    else
        echo "❌ Error injecting key."
        return 1
    fi
}


Check_Router()
{
    echo "The script will now validate your root SSH key for authentication with your router."

    KEY_FILE="/root/.ssh/id_ed25519"
    if [ -f "$KEY_FILE" ]; then
        echo "There is already a root SSH key on your system that will be used."
    else
        echo "Generating new secure ED25519 SSH keys for the root user..."
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        ssh-keygen -t ed25519 -N "" -f "$KEY_FILE" -C "asterisk-router-cron" 
        echo "SSH key generation complete."
    fi

    # Discover network layout gateway context dynamically
    DEFAULT_IP=$(ip route | grep default | awk '{print $3}' | head -n 1)
    DEFAULT_IP=${DEFAULT_IP:-"192.168.1.1"}

    echo ""
    read -p "Enter your router's network IP address [$DEFAULT_IP]: " ROUTER_IP
    ROUTER_IP=${ROUTER_IP:-$DEFAULT_IP}
    
    echo "Checking connectivity with: $ROUTER_IP"

    # Verify direct route response
    if ! ping -c 1 -W 2 "$ROUTER_IP" > /dev/null 2>&1; then
        echo "------------------------------------------------------------------"
        echo "CRITICAL: Router at $ROUTER_IP does not respond at all (Ping Failed)."
        echo "Please correct the problem and try the script again."
        echo "------------------------------------------------------------------"
        exit 1
    fi

    # Audit default SSH port response
    if ! nc -z -w 3 "$ROUTER_IP" 22 > /dev/null 2>&1; then
        echo "------------------------------------------------------------------"
        echo "CRITICAL: Router is online but is not responding to SSH (Port 22 closed)."
        echo "Please enable the SSH service for LAN in your router and re-run this script."
        echo "***Be sure you do NOT enable WAN SSH access.***"
        echo "------------------------------------------------------------------"
        exit 1
    fi

    echo "Router active. Preparing remote public key installation..."
    echo "NOTE: You will be prompted to enter your router's root password below."

    #use the following for openwrt
    # cat ~/.ssh/id_ed25519.pub | ssh root@"$ROUTER_IP" "mkdir -p /etc/dropbear && cat >> /etc/dropbear/authorized_keys && chmod 0600 /etc/dropbear/authorized_keys"

    # ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" root@"$ROUTER_IP"
    if ! copy_ssh_key; then
        echo "ERROR: Key verification handshake failed. Confirm router credentials and re-run this script."
        exit 1
    fi

    # Active validation loop using a temporary transfer payload
    echo "verification-token" > /tmp/text.tmp
    SCP_FLAGS="-i $KEY_FILE -o StrictHostKeyChecking=no"

    if ! scp $SCP_FLAGS /tmp/text.tmp root@"$ROUTER_IP":/tmp/text.tmp > /dev/null 2>&1; then
        # Automatic fallback evaluation for BusyBox/OpenWrt target architectures
        if ! scp -O $SCP_FLAGS /tmp/text.tmp root@"$ROUTER_IP":/tmp/text.tmp > /dev/null 2>&1; then
            echo "------------------------------------------------------------------"
            echo "CRITICAL: Router is not responding to modern or legacy SCP transfers."
            echo "If using OpenWrt, fix this by running this command on the router:"
            echo "'opkg update && opkg install openssh-sftp-server'"
            echo "------------------------------------------------------------------"
            rm -f /tmp/text.tmp
            exit 1
        else
            echo "It has been determined that the \"-O\" command line option is required for"
            echo "your router.  If scp is used in AutoBlock.conf, you will need to use -O."
        fi
    fi

    if ! rsync -avz -e "ssh -i $KEY_FILE -o StrictHostKeyChecking=no" /tmp/text.tmp root@"$ROUTER_IP":/tmp/text.tmp > /dev/null 2>&1; then
        echo "------------------------------------------------------------------"
        echo "CRITICAL: Router is not responding to Rsync connections."
        echo "Fix this by running this command on the router:"
        echo "'opkg update && opkg install rsync'"
        echo "------------------------------------------------------------------"
        rm -f /tmp/text.tmp
        exit 1
    fi

    # Clean up structural footprint tests
    ssh -i "$KEY_FILE" root@"$ROUTER_IP" "rm -f /tmp/text.tmp"
    rm -f /tmp/text.tmp
    echo "✅ Router communication verified."
}




# ------------------------------------------------------------------------------
# 1. ROOT EXECUTOR CHECK
# ------------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "=================================================================="
    echo "ERROR: Root privileges are required to install AutoBlock."
    echo "Please re-run this installer using: sudo $0"
    echo "=================================================================="
    exit 1
fi

echo "=================================================================="
echo " Starting AutoBlock Installation"
echo "=================================================================="

# ------------------------------------------------------------------------------
# ASTERISK SYSTEM VERIFICATION
# ------------------------------------------------------------------------------
if ! command -v asterisk >/dev/null 2>&1 && [ ! -d /etc/asterisk ]; then
    echo "⚠️  WARNING: Asterisk was not found on this system."
    prompt_user "Asterisk was not found on this system, install AutoBlock anyway?"
fi


# call function to make sure dependencies are installed.
check_and_install_dependencies

# Download and compile the code
Compile_Code

# ------------------------------------------------------------------------------
# ARCHITECTURE PROMPT & INTEGRATED ROUTER/SSH MODULE
# ------------------------------------------------------------------------------
echo ""
echo "------------------------------------------------------------------"
echo "                    Firewall Architecture Decision"
echo "    The default configuration of AutoBlock is to run Asterisk and AutoBlock"
echo "on the same server and send an IpSet to the router for it to block."
echo "This code works best with routers running OpenWrt firmware, however any"
echo "router that has support for ping, ssh, rsync, scp, and ipsets should work fine."
echo ""
echo "    Non-standard installations would include situations where asterisk and"
echo "AutoBlock are running on the router itself.  Or where the asterisk server's"
echo "firewall is used instead of the routers.  These installations are possible"
echo "by modifying the AutoBlock.conf file, but cannot be done automatically here."
echo "------------------------------------------------------------------"
read -p "Are you planning on using the default installation? (y/n): " router_choice

if [[ "$router_choice" =~ ^[Yy]$ ]]; then
    Check_Router
else
    echo ""
    echo "------------------------------------------------------------------"
    echo "NOTICE: Since you are creating a non-standard installation, you"
    echo "will need to configure your firewall separately from this script."
    echo "------------------------------------------------------------------"
    echo "Skipping SSH router automation..."
fi



# Map production binary to system path
echo "Finishing up install."
cp -f "$TARGET_DIR/AutoBlock" /usr/bin/AutoBlock
chmod 755 /usr/bin/AutoBlock
chown root:root /usr/bin/AutoBlock

# copy config file
if [ ! -f /etc/AutoBlock.conf ]; then
   cp "$TARGET_DIR/AutoBlock.conf" /etc/AutoBlock.conf
   chmod 644 /etc/AutoBlock.conf
   chown root:root /etc/AutoBlock.conf
   echo "✅ Default configuration file deployed to /etc/AutoBlock.conf"
else
    echo "ℹ️ Existing /etc/AutoBlock.conf file detected. Preserving user configurations."
fi

# INTERACTIVE CRON AUTOMATION SCHEDULER
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "AutoBlock is now installed and will now be added as a cron job."
echo "=================================================================="
echo "How frequently would you like AutoBlock to check Asterisk logs for hackers?"
echo "Options: 15m, 30m, 1h, 12h, 24h, q"
echo "If you want to skip setting up the cron job, enter 'q' "
echo "------------------------------------------------------------------"
while true; do
    read -p "Enter selection: " CRON_CHOICE
    case "$CRON_CHOICE" in
        # A standard crontab requires 5 blocks (minute hour day month weekday).
        15m) CRON_TIME="*/15 * * * *"; break ;;
        30m) CRON_TIME="*/30 * * * *"; break ;;
        1h)  CRON_TIME="0 * * * *"; break ;;
        12h) CRON_TIME="0 */12 * * *"; break ;;
        24h) CRON_TIME="0 0 * * *"; break ;;
        q|Q) CRON_TIME="skip"; break ;;
        *)   echo "Invalid option. Please type exactly: 15m, 30m, 1h, 12h, or 24h." ;;
    esac
done


if [ "$CRON_TIME" != "skip" ]; then

    # 1. Define the temporary file location
    local temp_cron_file="$TARGET_DIR/autoblock_cron.tmp"
    
    # 2. Define the exact line we want to add
    local cron_job="$CRON_TIME /usr/bin/AutoBlock > /dev/null 2>&1"

    echo "Scheduling automated task..."

    # 3. Step-by-step file assembly
    # Extract the current crontab, hiding errors if it doesn't exist
    crontab -l > "$temp_cron_file" 2>/dev/null

    # Strip out any pre-existing AutoBlock entries to avoid duplicates
    # We use a secondary temp file to handle the clean stream transfer safely
    grep -v "/usr/bin/AutoBlock" "$temp_cron_file" > "${temp_cron_file}.clean" 2>/dev/null
    
    # Append our new cron job tracking line to the bottom of the file
    echo "$cron_job" >> "${temp_cron_file}.clean"

    # 4. Commit the new file to the system scheduler
    crontab "${temp_cron_file}.clean"

    # 5. Clean up our workspace files
    rm -f "$temp_cron_file" "${temp_cron_file}.clean"

    echo "✅ Automation successfully scheduled in root's crontab."
else
    echo "Skipping cron job creation at user request."
fi
  

# ------------------------------------------------------------------------------        


# CONCLUSION
# ------------------------------------------------------------------------------

echo "=================================================================="
echo " SUCCESS: AutoBlock Suite Core Installation Complete!"
echo "=================================================================="
echo " IMPORTANT MANUAL ACTIONS REQUIRED:"
echo " The configuration file handles critical network credentials and"
echo " has been locked down so it can only be altered by the system root."
echo ""
echo " To customize your parameters, you must run:"
echo "     sudo nano /etc/AutoBlock.conf"
echo ""
echo " File Permissions Matrix Implemented:"
echo "  - /usr/bin/AutoBlock: Executable by all, modification locked to Root."
echo "  - /etc/AutoBlock.conf: Readable by all, modification locked to Root."
echo "=================================================================="
exit 0

