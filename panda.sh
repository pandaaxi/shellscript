#!/bin/bash

# Menu

main_menu() {
    while true; do
        clear
        echo "▶ Main Menu"
        echo "V0.3.6"
        echo "------------------------"
        echo "1. System Information Query"
        echo "2. System Update"
        echo "3. System Clean"
        echo "------------------------"
        echo "4. System Tools ▶"
        echo "5. Media Unblock Check ▶"
        echo "6. Docker Management ▶"
        echo "7. Trace Route ▶"
        echo "8. WARP Management ▶"
        echo "9. WGCF Management ▶"
        echo "10. BBR Management ▶"
        echo "11. Realm Management ▶"
        echo "------------------------"
        echo "00. Script Update"

        echo "99. Uninstall Panda"
        echo "0. Quit"
        echo "------------------------"
        read -p "Enter your choice: " choice


        case $choice in
            1)
                system_info_query
                ;;
            2)
                system_update
                ;;
            3)
                system_clean
                ;;
            4)
                system_tools
                ;;
            5)
                media_unblock_check
                ;;
            6)
                docker_management
                ;;
            7)
                trace_route_menu
                ;;
            8)
                warp_management
                ;;
            9)
                wgcf
                ;;
            10)
                bbr_management
                ;;
            11)
                realm_management
                ;;
            00)
                update_script
                ;;
            99)
                uninstall_panda
                ;;
            0)
                quit_script
                ;;
            *)
                echo "Invalid input! Please enter a valid option."
                ;;
        esac
        read -p "Press any key to continue..." key
    done
}

# Function to quit the script
quit_script() {
    echo "Quitting the script. Goodbye!"
    exit 0
}

# Function to handle post-submenu actions
break_end() {
    echo "Returning to the previous menu..."
    read -p "Press any key to continue..." key
}

# Function to open necessary iptables ports after SSH port change
iptables_open() {
    new_port=$1
    echo "Updating iptables to allow new SSH port: $new_port"
    
    # Allow the new SSH port in iptables (IPv4 and IPv6)
    iptables -A INPUT -p tcp --dport $new_port -j ACCEPT
    ip6tables -A INPUT -p tcp --dport $new_port -j ACCEPT
    
    # Save iptables changes to ensure they persist after reboot
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    echo "iptables rules updated to allow SSH on port $new_port."
}

# Function to create a symbolic link to panda.sh
install_panda() {
    script_path=$(readlink -f "$0")
    ln -sf "$script_path" /usr/local/bin/panda
    chmod +x /usr/local/bin/panda
    echo "Panda has been installed as 'panda'. You can now run it by typing 'panda'."
}

# Function to uninstall the symbolic link
uninstall_panda() {
    if [ -f /usr/local/bin/panda ]; then
        rm /usr/local/bin/panda
        echo "Panda has been uninstalled. You can no longer call it via 'panda'."
    else
        echo "Panda is not installed."
    fi
}

# Check if the script is being run for the first time and install it
if [[ "$0" == "./panda.sh" ]]; then
    install_panda
fi

# Non Manual Function
output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        NR > 2 { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }

            printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)
}

ip_address() {
ipv4_address=$(curl -s ipv4.ip.sb)
ipv6_address=$(curl -s --max-time 1 ipv6.ip.sb)
}

current_timezone() {
    if grep -q 'Alpine' /etc/issue; then
       date +"%Z %z"
    else
       timedatectl | grep "Time zone" | awk '{print $3}'
    fi

}

# Function Script

# Function to retrieve and display system information
system_info_query() {
    clear
    # Function: Get IPv4 and IPv6 addresses
    ip_address

    if [ "$(uname -m)" == "x86_64" ]; then
      cpu_info=$(cat /proc/cpuinfo | grep 'model name' | uniq | sed -e 's/model name[[:space:]]*: //')
    else
      cpu_info=$(lscpu | grep 'BIOS Model name' | awk -F': ' '{print $2}' | sed 's/^[ \t]*//')
    fi

    if [ -f /etc/alpine-release ]; then
        # Use the following command for Alpine Linux to get CPU usage
        cpu_usage_percent=$(top -bn1 | grep '^CPU' | awk '{print " "$4}' | cut -c 1-2)
    else
        # Use the following command for other systems to get CPU usage
        cpu_usage_percent=$(top -bn1 | grep "Cpu(s)" | awk '{print " "$2}')
    fi

    cpu_cores=$(nproc)
    # Extract DNS information
    dns_ipv4=$(grep -E "^nameserver[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}$" /etc/resolv.conf | awk '{print $2}' | paste -sd ", " -)
    dns_ipv6=$(grep -E "^nameserver[[:space:]]+([a-fA-F0-9:]+)$" /etc/resolv.conf | awk '{print $2}' | paste -sd ", " -)

    mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')

    disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')

    country=$(curl -s ipinfo.io/country)
    city=$(curl -s ipinfo.io/city)

    isp_info=$(curl -s ipinfo.io/org)

    cpu_arch=$(uname -m)

    hostname=$(hostname)

    kernel_version=$(uname -r)

    congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
    queue_algorithm=$(sysctl -n net.core.default_qdisc)

    # Attempt to use lsb_release to get system information
    os_info=$(lsb_release -ds 2>/dev/null)

    # If the lsb_release command fails, try other methods
    if [ -z "$os_info" ]; then
      # Check common release files
      if [ -f "/etc/os-release" ]; then
        os_info=$(source /etc/os-release && echo "$PRETTY_NAME")
      elif [ -f "/etc/debian_version" ]; then
        os_info="Debian $(cat /etc/debian_version)"
      elif [ -f "/etc/redhat-release" ]; then
        os_info=$(cat /etc/redhat-release)
      else
        os_info="Unknown"
      fi
    fi

    output_status

    current_time=$(date "+%Y-%m-%d %I:%M %p")

    swap_used=$(free -m | awk 'NR==3{print $3}')
    swap_total=$(free -m | awk 'NR==3{print $2}')

    if [ "$swap_total" -eq 0 ]; then
        swap_percentage=0
    else
        swap_percentage=$((swap_used * 100 / swap_total))
    fi

    swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

    runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d days ", run_days); if (run_hours > 0) printf("%d hrs ", run_hours); printf("%d mins\n", run_minutes)}')

    timezone=$(current_timezone)

    echo ""
    echo "System Information Query"
    echo "------------------------"
    echo "Hostname: $hostname"
    echo "ISP: $isp_info"
    echo "------------------------"
    echo "OS Version: $os_info"
    echo "Linux Version: $kernel_version"
    echo "------------------------"
    echo "CPU Architecture: $cpu_arch"
    echo "CPU Model: $cpu_info"
    echo "CPU Cores: $cpu_cores"
    echo "------------------------"
    echo "CPU Usage: $cpu_usage_percent%"
    echo "Physical Memory: $mem_info"
    echo "Swap Memory: $swap_info"
    echo "Disk Usage: $disk_info"
    echo "------------------------"
    echo "$output"
    echo "------------------------"
    echo "Network Congestion Algorithm: $congestion_algorithm $queue_algorithm"
    echo "------------------------"
    echo "Public IPv4 Address: $ipv4_address"
    echo "Public IPv6 Address: $ipv6_address"
    echo "------------------------"
    echo "DNS IPv4: $dns_ipv4"
    echo "DNS IPv6: $dns_ipv6"
    echo "------------------------"
    echo "Geographic Location: $country $city"
    echo "System Timezone: $timezone"
    echo "System Time: $current_time"
    echo "------------------------"
    echo "System Uptime: $runtime"
    echo
}

# Function to update the system
system_update() {

    # Update system on Debian-based systems
    if [ -f "/etc/debian_version" ]; then
        apt update -y && apt upgrade -y && apt full-upgrade -y && apt autoremove -y && apt autoclean -y
    fi

    # Update system on Red Hat-based systems
    if [ -f "/etc/redhat-release" ]; then
        yum -y update
    fi

    # Update system on Alpine Linux
    if [ -f "/etc/alpine-release" ]; then
        apk update && apk upgrade
    fi

}

# Function to clean up the system
system_clean() {
    clean_debian() {
        apt autoremove --purge -y
        apt clean -y
        apt autoclean -y
        apt remove --purge $(dpkg -l | awk '/^rc/ {print $2}') -y
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
        apt remove --purge $(dpkg -l | awk '/^ii linux-(image|headers)-[^ ]+/{print $2}' | grep -v $(uname -r | sed 's/-.*//') | xargs) -y
    }

    clean_redhat() {
        yum autoremove -y
        yum clean all
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
        yum remove $(rpm -q kernel | grep -v $(uname -r)) -y
    }

    clean_alpine() {
        apk del --purge $(apk info --installed | awk '{print $1}' | grep -v $(apk info --available | awk '{print $1}'))
        apk autoremove
        apk cache clean
        rm -rf /var/log/*
        rm -rf /var/cache/apk/*

    }

    # Main script
    if [ -f "/etc/debian_version" ]; then
        # Debian-based systems
        clean_debian
    elif [ -f "/etc/redhat-release" ]; then
        # Red Hat-based systems
        clean_redhat
    elif [ -f "/etc/alpine-release" ]; then
        # Alpine Linux
        clean_alpine
    fi

}

# Sub menu for System Tools
system_tools() {
while true; do
    # Automatically detect SSH port from /etc/ssh/sshd_config
    current_ssh_port=$(grep -P '^\s*Port\s+\d+' /etc/ssh/sshd_config | awk '{print $2}')
    if [ -z "$current_ssh_port" ]; then
        current_ssh_port=22 # Default SSH port
    fi

    clear
    echo "▶ System Tools"
    echo "------------------------"
    echo "Current SSH Port: $current_ssh_port"
    echo "------------------------"
    echo "1. Set DNS Address"
    echo "2. Set SSH Port"
    echo "3. Manage SSH Key Authentication"
    echo "------------------------"
    echo "4. Install Fail2ban"
    echo "5. Fail2ban Status"
    echo "------------------------"
    echo "5. Swap Memory Management"
    echo "7. Reboot Server"
    echo "------------------------"
    echo "0. Return to Main Menu"
    echo "------------------------"
    read -p "Enter your choice: " sub_choice

    case $sub_choice in
        1)
            set_dns
            ;;
        2)
            echo "Enter the new SSH port: "
            read new_port
            set_ssh_port $new_port
            ;;
        3)
            manage_ssh_key_auth
            ;;
        4)
            install_fail2ban
            ;;
        5)
            fail2ban_status
            ;;
        5)
            while true; do
                swap_used=$(free -m | awk 'NR==3{print $3}')
                swap_total=$(free -m | awk 'NR==3{print $2}')

                if [ "$swap_total" -eq 0 ]; then
                swap_percentage=0
                else
                swap_percentage=$((swap_used * 100 / swap_total))
                fi

                swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"
                clear
                echo "Current Swap Memory: $swap_info"
                echo ""
                echo "Swap Memory Management"
                echo "------------------------"
                echo "1. Add 1024MB Swap"
                echo "2. Add 2048MB Swap"
                echo "3. Manually Add Swap Memory"
                echo "4. Disable Swap"
                echo "------------------------"
                echo "0. Return to System Tools"
                echo "------------------------"
                read -p "Enter your choice: " swap_choice

                case $swap_choice in
                    1) add_swap 1024 ;;
                    2) add_swap 2048 ;;
                    3) 
                        echo "Enter the swap size in MB: "
                        read swap_size
                        add_swap $swap_size
                        ;;
                    4) disable_swap ;;
                    0) break ;;
                    *) echo "Invalid choice!" ;;
                esac
            done
            ;;
        6)
            reboot_server
            ;;
        0)
            break  # Exit the loop, return to the main menu
            ;;
        *)
            echo "Invalid input!"
            ;;
    esac
    break_end
done
}

# Sub menu for Media Unblock Check
media_unblock_check() {
    while true; do
        clear
        echo "▶ Media Unblock Check"
        echo "------------------------"
        echo "1. DNS Unblock Testing (IPv4)"
        echo "2. DNS Unblock Testing (IPv6)"
        echo "------------------------"
        echo "0. Return to Main Menu"
        echo "------------------------"
        read -p "Enter your choice: " sub_choice

        case $sub_choice in
            1)
                bash <(curl -Ls IP.Check.Place) -4
                ;;
            2)
                bash <(curl -Ls IP.Check.Place) -6
                ;;
            0) break ;;
            *) echo "Invalid input!" ;;
        esac
        read -p "Press any key to continue..." key
    done
}

# Sub menu for Trace Route
trace_route_menu() {
    while true; do
        clear
        echo "▶ Trace Route"
        echo "------------------------"
        echo "1. Install"
        echo "2. Trace Lsize"
        echo "3. Trace Ssize"
 echo "4. Trace Manual"

        echo "------------------------"
        echo "0. Return to Main Menu"
        echo "------------------------"
        read -p "Enter your choice: " sub_choice

        case $sub_choice in
            1)
                clear
                curl nxtrace.org/nt | bash
                ;;
            2)
                clear
                read -p "Enter the IP address to trace: " ip_address
                nexttrace -T --psize 1450 $ip_address -p 80
                read -p "Press any key to continue..." key
                ;;
            3)
                clear
                read -p "Enter the IP address to trace: " ip_address
                nexttrace -T --psize 64 $ip_address -p 80
                read -p "Press any key to continue..." key
                ;;
            4)
                trace_manual
                read -p "Press any key to continue..." key
                ;;

            0)
                break  # Exit the loop, return to the main menu
                ;;
            *)
                echo "Invalid input!"
                ;;
        esac
    done
}
# Function for manual trace route
trace_manual() {
    clear
    read -p "Enter the IP address to trace: " -r ip_address

    read -p "Enter optional packet size (--psize, default 1450): " -r psize

    local command="nexttrace -T $ip_address -p 80"

    if [ -n "$psize" ]; then
        command="nexttrace -T --psize $psize $ip_address -p 80"
    else
        command="nexttrace -T --psize 1450 $ip_address -p 80"
    fi

    echo "Running command: $command"
    eval "$command"
}

# Function to test DNS response time and update resolv.conf with the best DNS group
set_dns() {
    #-----------------------------
    # Config
    #-----------------------------
    local domain="google.com"   # test target for dig
    local PING_TIMEOUT=1        # seconds
    local BIG=999999            # large sentinel value

    # IPv4
    local cf_ipv4_primary="1.1.1.1"
    local cf_ipv4_secondary="1.0.0.1"
    local gg_ipv4_primary="8.8.8.8"
    local gg_ipv4_secondary="8.8.4.4"

    # IPv6
    local cf_ipv6_primary="2606:4700:4700::1111"
    local cf_ipv6_secondary="2606:4700:4700::1001"
    local gg_ipv6_primary="2001:4860:4860::8888"
    local gg_ipv6_secondary="2001:4860:4860::8844"

    #-----------------------------
    # Root check for resolv.conf
    #-----------------------------
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must run as root to update /etc/resolv.conf."
        return 1
    fi

    #-----------------------------
    # Ensure dig is installed
    #-----------------------------
    ensure_dig() {
        if command -v dig >/dev/null 2>&1; then
            return 0
        fi
        echo "dig not found; attempting to install..."

        # Best-effort detection of package manager
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y && apt-get install -y dnsutils
        elif command -v apt >/dev/null 2>&1; then
            apt update -y && apt install -y dnsutils
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bind-utils
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bind-utils
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache bind-tools
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm bind
        elif command -v zypper >/dev/null 2>&1; then
            zypper --non-interactive install bind-utils
        else
            echo "Could not detect supported package manager. Please install 'dig' manually (dnsutils/bind-utils/bind-tools)."
            return 1
        fi

        if ! command -v dig >/dev/null 2>&1; then
            echo "Installation reported success but 'dig' still not found. Aborting."
            return 1
        fi
    }
    ensure_dig || return 1

    #-----------------------------
    # Helpers: company, IPv6 check
    #-----------------------------
    get_company() {
        case "$1" in
            "$cf_ipv4_primary"|"$cf_ipv4_secondary"|"$cf_ipv6_primary"|"$cf_ipv6_secondary") echo "Cloudflare" ;;
            "$gg_ipv4_primary"|"$gg_ipv4_secondary"|"$gg_ipv6_primary"|"$gg_ipv6_secondary") echo "Google" ;;
            *) echo "Unknown" ;;
        esac
    }

    is_ipv6() { case "$1" in *:*) return 0 ;; *) return 1 ;; esac; }

    #-----------------------------
    # Helpers: measure ping & dig
    #-----------------------------
    ping_ms() {
        # Returns integer ms or BIG on failure
        local host="$1"
        local out
        if is_ipv6 "$host"; then
            # Use ping -6 if available, otherwise ping6
            if ping -6 -c 1 -W "$PING_TIMEOUT" -n "$host" >/dev/null 2>&1; then
                out=$(ping -6 -c 1 -W "$PING_TIMEOUT" -n "$host" 2>/dev/null)
            elif command -v ping6 >/dev/null 2>&1; then
                out=$(ping6 -c 1 -W "$PING_TIMEOUT" -n "$host" 2>/dev/null)
            else
                echo "$BIG"; return
            fi
        else
            out=$(ping -c 1 -W "$PING_TIMEOUT" -n "$host" 2>/dev/null) || { echo "$BIG"; return; }
        fi
        # Extract time=XX.xxx ms
        # Handle locales by grepping "time=" and stripping " ms"
        local t
        t=$(printf "%s\n" "$out" | sed -n 's/.*time=\([0-9.]\+\).*/\1/p' | head -n1)
        if [ -z "$t" ]; then echo "$BIG"; else
            # round to integer ms
            awk -v x="$t" 'BEGIN{printf("%d\n", (x<0)?0:int(x+0.5))}'
        fi
    }

    dig_ms() {
        # Returns integer ms (Query time) or BIG on failure
        local server="$1" tgt="$2"
        local out
        out=$(dig @"$server" "$tgt" +stats +time=2 +tries=1 2>/dev/null)
        local t
        t=$(printf "%s\n" "$out" | awk '/Query time:/{print $4; exit}')
        if [ -z "$t" ]; then echo "$BIG"; else echo "$t"; fi
    }

    measure_server() {
        # Emits: "<server> ping=<ms> dig=<ms> combined=<ms>"
        local s="$1"
        local p d c
        p=$(ping_ms "$s")
        d=$(dig_ms  "$s" "$domain")
        # Combined score: prefer real DNS performance (dig) but include network RTT.
        # Weight dig more heavily (e.g., 70% dig, 30% ping).
        # If any metric is BIG (failed), it dominates.
        if [ "$p" -ge "$BIG" ] || [ "$d" -ge "$BIG" ]; then
            c="$BIG"
        else
            # c = 0.7*dig + 0.3*ping, rounded
            c=$(awk -v dd="$d" -v pp="$p" 'BEGIN{printf("%d\n", int((0.7*dd + 0.3*pp)+0.5))}')
        fi
        echo "$s ping=$p dig=$d combined=$c"
    }

    better_of_two() {
        # Usage: better_of_two <A> <B>
        # Prints: "<winner_server> <winner_company> <winner_combined>"
        local A="$1" B="$2"
        local ra rb ca cb pa pb da db
        ra=$(measure_server "$A")
        rb=$(measure_server "$B")

        ca=$(printf "%s\n" "$ra" | sed -n 's/.*combined=\([0-9]\+\).*/\1/p')
        cb=$(printf "%s\n" "$rb" | sed -n 's/.*combined=\([0-9]\+\).*/\1/p')
        pa=$(printf "%s\n" "$ra" | sed -n 's/.*ping=\([0-9]\+\).*/\1/p')
        pb=$(printf "%s\n" "$rb" | sed -n 's/.*ping=\([0-9]\+\).*/\1/p')
        da=$(printf "%s\n" "$ra" | sed -n 's/.*dig=\([0-9]\+\).*/\1/p')
        db=$(printf "%s\n" "$rb" | sed -n 's/.*dig=\([0-9]\+\).*/\1/p')

        echo "  $ra"
        echo "  $rb"

        local win=; local wscore=
        if [ "$ca" -lt "$cb" ]; then
            win="$A"; wscore="$ca"
        elif [ "$cb" -lt "$ca" ]; then
            win="$B"; wscore="$cb"
        else
            # Tie on combined — break by lower dig, then lower ping
            if [ "$da" -lt "$db" ]; then
                win="$A"; wscore="$ca"
            elif [ "$db" -lt "$da" ]; then
                win="$B"; wscore="$cb"
            else
                if [ "$pa" -lt "$pb" ]; then
                    win="$A"; wscore="$ca"
                else
                    win="$B"; wscore="$cb"
                fi
            fi
        fi

        local comp; comp=$(get_company "$win")
        echo "$win $comp $wscore"
    }

    #-----------------------------
    # IPv4 logic (with retest)
    #-----------------------------
    echo "=== IPv4 tests ==="
    local primary_winner_ipv4 primary_company_ipv4
    read -r primary_winner_ipv4 primary_company_ipv4 _ < <(better_of_two "$cf_ipv4_primary" "$gg_ipv4_primary")
    echo "Primary IPv4 winner: $primary_winner_ipv4 ($primary_company_ipv4)"

    local secondary_winner_r1_ipv4 secondary_company_r1_ipv4
    read -r secondary_winner_r1_ipv4 secondary_company_r1_ipv4 _ < <(better_of_two "$cf_ipv4_secondary" "$gg_ipv4_secondary")
    echo "Secondary IPv4 Round 1 winner: $secondary_winner_r1_ipv4 ($secondary_company_r1_ipv4)"

    local final_ipv4_dns=()
    if [ "$secondary_company_r1_ipv4" != "$primary_company_ipv4" ]; then
        echo "Secondary IPv4 R1 company differs from primary; retesting secondaries ..."
        local secondary_winner_r2_ipv4 secondary_company_r2_ipv4
        read -r secondary_winner_r2_ipv4 secondary_company_r2_ipv4 _ < <(better_of_two "$cf_ipv4_secondary" "$gg_ipv4_secondary")
        echo "Secondary IPv4 Round 2 winner: $secondary_winner_r2_ipv4 ($secondary_company_r2_ipv4)"

        if [ "$secondary_company_r2_ipv4" = "$primary_company_ipv4" ]; then
            final_ipv4_dns+=("$primary_winner_ipv4")
            if [ "$primary_company_ipv4" = "Cloudflare" ]; then
                final_ipv4_dns+=("$cf_ipv4_secondary")
            else
                final_ipv4_dns+=("$gg_ipv4_secondary")
            fi
        else
            final_ipv4_dns+=("$primary_winner_ipv4")
        fi
    else
        final_ipv4_dns+=("$primary_winner_ipv4" "$secondary_winner_r1_ipv4")
    fi

    #-----------------------------
    # IPv6 logic (with retest)
    #-----------------------------
    echo
    echo "=== IPv6 tests ==="
    local primary_winner_ipv6 primary_company_ipv6
    read -r primary_winner_ipv6 primary_company_ipv6 _ < <(better_of_two "$cf_ipv6_primary" "$gg_ipv6_primary")
    echo "Primary IPv6 winner: $primary_winner_ipv6 ($primary_company_ipv6)"

    local secondary_winner_r1_ipv6 secondary_company_r1_ipv6
    read -r secondary_winner_r1_ipv6 secondary_company_r1_ipv6 _ < <(better_of_two "$cf_ipv6_secondary" "$gg_ipv6_secondary")
    echo "Secondary IPv6 Round 1 winner: $secondary_winner_r1_ipv6 ($secondary_company_r1_ipv6)"

    local final_ipv6_dns=()
    if [ "$secondary_company_r1_ipv6" != "$primary_company_ipv6" ]; then
        echo "Secondary IPv6 R1 company differs from primary; retesting secondaries ..."
        local secondary_winner_r2_ipv6 secondary_company_r2_ipv6
        read -r secondary_winner_r2_ipv6 secondary_company_r2_ipv6 _ < <(better_of_two "$cf_ipv6_secondary" "$gg_ipv6_secondary")
        echo "Secondary IPv6 Round 2 winner: $secondary_winner_r2_ipv6 ($secondary_company_r2_ipv6)"

        if [ "$secondary_company_r2_ipv6" = "$primary_company_ipv6" ]; then
            final_ipv6_dns+=("$primary_winner_ipv6")
            if [ "$primary_company_ipv6" = "Cloudflare" ]; then
                final_ipv6_dns+=("$cf_ipv6_secondary")
            else
                final_ipv6_dns+=("$gg_ipv6_secondary")
            fi
        else
            final_ipv6_dns+=("$primary_winner_ipv6")
        fi
    else
        final_ipv6_dns+=("$primary_winner_ipv6" "$secondary_winner_r1_ipv6")
    fi

    #-----------------------------
    # Apply to resolv.conf
    #-----------------------------
    echo
    echo "Final IPv4 DNS: ${final_ipv4_dns[*]}"
    echo "Final IPv6 DNS: ${final_ipv6_dns[*]}"

    if [ "${#final_ipv4_dns[@]}" -eq 0 ] && [ "${#final_ipv6_dns[@]}" -eq 0 ]; then
        echo "No DNS servers selected; aborting."
        return 1
    fi

    echo "Updating /etc/resolv.conf ..."
    {
        for s in "${final_ipv4_dns[@]}"; do echo "nameserver $s"; done
        for s in "${final_ipv6_dns[@]}"; do echo "nameserver $s"; done
    } > /etc/resolv.conf

    echo "DNS settings updated."
}



set_ssh_port() {
    new_port=$1

    # Backup the SSH configuration file
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Ensure the Port line is uncommented and updated
    sed -i 's/^\s*#\?\s*Port/Port/' /etc/ssh/sshd_config

    # Replace the port number in the SSH configuration file
    sed -i "s/Port [0-9]\+/Port $new_port/g" /etc/ssh/sshd_config

    # Restart the SSH service
    restart_ssh
    echo "SSH port has been changed to: $new_port"

    clear
    iptables_open
 if [ -f "/etc/debian_version" ]; then
 # Debian-based systems
 apt remove --purge -y iptables-persistent ufw > /dev/null 2>&1
 elif [ -f "/etc/redhat-release" ]; then
 # Red Hat-based systems
 yum remove -y firewalld iptables-services > /dev/null 2>&1
 elif [ -f "/etc/alpine-release" ]; then
 # Alpine Linux
 apk del --purge iptables-services > /dev/null 2>&1
 fi
}

manage_ssh_key_auth() {
    # Generate an SSH key pair
    ssh-keygen -t ed25519 -C "xxxx@gmail.com" -f /root/.ssh/sshkey -N ""

    # Add the public key to authorized_keys
    cat ~/.ssh/sshkey.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

    ip_address
    echo -e "Private key information has been generated. Be sure to copy and save it as a file named ${huang}${ipv4_address}_ssh.key${bai} for future SSH logins."
    echo "--------------------------------"
    cat ~/.ssh/sshkey
    echo "--------------------------------"

    # Update SSH configuration for key-based authentication
    sed -i -e 's/^\s*#\?\s*PermitRootLogin .*/PermitRootLogin prohibit-password/' \
           -e 's/^\s*#\?\s*PasswordAuthentication .*/PasswordAuthentication no/' \
           -e 's/^\s*#\?\s*PubkeyAuthentication .*/PubkeyAuthentication yes/' \
           -e 's/^\s*#\?\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*
    echo -e "${lv}ROOT key-based login has been enabled. Password login for ROOT is disabled. Changes will take effect on reconnection.${bai}"
}

add_swap() {
    swap_size=$1

    # Turn off any existing swap
    swapoff -a

    # Remove any existing swapfile
    rm -f /swapfile

    # Create a new swapfile of the specified size
    dd if=/dev/zero of=/swapfile bs=1M count=$swap_size
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    # Add the swapfile to /etc/fstab for persistence
    if ! grep -q '/swapfile swap swap defaults 0 0' /etc/fstab; then
        echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    fi

    echo -e "Swap memory of size ${huang}${swap_size}${bai}MB has been added."
}

disable_swap() {
    # Disable swap memory
    swapoff /swapfile

    # Remove the swapfile entry from /etc/fstab
    sed -i '/\/swapfile swap swap defaults 0 0/d' /etc/fstab

    # Remove the swapfile
    rm -f /swapfile

    echo "Swap memory disabled."
}

reboot_server() {
    read -p "$(echo -e "${huang}Do you want to reboot the server now? (Y/N): ${bai}")" rboot
    case "$rboot" in
        [Yy])
            echo "Rebooting..."
            reboot
            ;;
        [Nn])
            echo "Reboot canceled."
            ;;
        *)
            echo "Invalid choice, please enter Y or N."
            ;;
    esac
}

# Function to install Fail2Ban
install_fail2ban() {
  set -e

  echo "Detecting SSH port(s)..."

  detect_ssh_ports() {
    local ports=""
    if command -v sshd >/dev/null 2>&1; then
      ports=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | paste -sd, -) || true
      if [ -z "$ports" ]; then
        ports=$(sshd -T -C user=root,host="$(hostname)",addr=127.0.0.1 2>/dev/null \
                | awk '/^port /{print $2}' | paste -sd, -) || true
      fi
    fi
    if [ -z "$ports" ] && [ -r /etc/ssh/sshd_config ]; then
      ports=$(awk '$1 ~ /^Port$/ && $2 ~ /^[0-9]+$/ { print $2 }' /etc/ssh/sshd_config | paste -sd, -)
    fi
    if [ -z "$ports" ]; then
      if command -v ss >/dev/null 2>&1; then
        ports=$(ss -tuln | awk '/ssh/ { if (match($0, /:([0-9]+)/, a)) print a[1] }' | sort -u | paste -sd, -)
      elif command -v netstat >/dev/null 2>&1; then
        ports=$(netstat -tuln 2>/dev/null | awk '/ssh/ { if (match($0, /:([0-9]+)/, a)) print a[1] }' | sort -u | paste -sd, -)
      fi
    fi
    [ -z "$ports" ] && ports="22"
    echo "$ports"
  }

  ssh_ports="$(detect_ssh_ports)"
  echo "Using SSH port(s): $ssh_ports"

  echo "Installing Fail2Ban..."
  if [ -f "/etc/debian_version" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt update -y
    apt install -y fail2ban
    if command -v systemctl >/dev/null 2>&1; then
      apt install -y python3-systemd
    fi
  elif [ -f "/etc/alpine-release" ]; then
    apk update
    apk add fail2ban
  else
    echo "Warning: unsupported distro. Install fail2ban manually."
  fi

  # Auto-pick firewall action
  pick_banaction() {
    if command -v nft >/dev/null 2>&1; then
      echo "nftables-multiport"
    elif command -v iptables >/dev/null 2>&1; then
      echo "iptables-multiport"
    else
      echo ""
    fi
  }
  banaction="$(pick_banaction)"

  have_systemd=false
  if command -v systemctl >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
    have_systemd=true
  fi

  auth_log=""
  if [ "$have_systemd" = false ]; then
    for f in /var/log/auth.log /var/log/secure /var/log/messages; do
      [ -f "$f" ] && auth_log="$f" && break
    done
    [ -z "$auth_log" ] && auth_log="/var/log/auth.log"
  fi

  mkdir -p /etc/fail2ban

  if [ "$have_systemd" = true ]; then
    cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
maxretry = 5
$( [ -n "$banaction" ] && echo "banaction = $banaction" )

[sshd]
enabled = true
port    = ${ssh_ports}
filter  = sshd
backend = systemd
journalmatch = _COMM=sshd
EOF
  else
    cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
maxretry = 5
$( [ -n "$banaction" ] && echo "banaction = $banaction" )

[sshd]
enabled = true
port    = ${ssh_ports}
filter  = sshd
backend = auto
logpath = ${auth_log}
EOF
  fi

  echo "Validating configuration..."
  if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client -t
  fi

  echo "Starting Fail2Ban..."
  if [ "$have_systemd" = true ]; then
    systemctl daemon-reload || true
    systemctl enable --now fail2ban || true
  else
    rc-update add fail2ban default || true
    rc-service fail2ban restart || rc-service fail2ban start
  fi

  # ---- WAIT FOR SERVER SOCKET (fixes your error) ----
  wait_for_f2b() {
    # Wait up to ~10s for the socket & a positive ping
    for i in $(seq 1 20); do
      if fail2ban-client ping >/dev/null 2>&1; then
        return 0
      fi
      sleep 0.5
    done
    return 1
  }

  if ! wait_for_f2b; then
    echo "Fail2Ban did not respond to ping in time. Showing service status:"
    if [ "$have_systemd" = true ]; then
      systemctl status --no-pager fail2ban || true
      journalctl -u fail2ban -n 50 --no-pager || true
    else
      rc-service fail2ban status || true
      tail -n 50 /var/log/fail2ban.log 2>/dev/null || true
    fi
  fi

  # Health summary (no scary errors)
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo
    echo "Fail2Ban summary:"
    fail2ban-client status || true
    echo
    fail2ban-client status sshd || true
  fi

  echo "Done. SSH jail configured on port(s): ${ssh_ports}"
  echo "Verify with: sudo fail2ban-client status sshd"
}


fail2ban_status() {
  set -u

  echo "=== Fail2Ban Status Report ==="

  # ---------- helpers ----------
  _resolve_tokens_to_ports() {
    # Convert tokens like "ssh, 19025" -> "22,19025" (if resolvable in /etc/services)
    local out=""
    local t resolved
    for t in $(echo "$1" | tr ',;' '  '); do
      t=$(echo "$t" | xargs)
      [ -z "$t" ] && continue
      if [[ "$t" =~ ^[0-9]+$ ]] || [[ "$t" =~ ^[0-9]+:[0-9]+$ ]] || [[ "$t" == "*" ]] || [[ "$t" == "all" ]]; then
        resolved="$t"
      else
        resolved=$(getent services "$t" 2>/dev/null | awk '{print $2}' | cut -d/ -f1 | head -n1)
        [ -z "$resolved" ] && resolved="$t"
      fi
      out="${out}${resolved},"
    done
    echo "${out%,}"
  }

  _detect_ssh_ports() {
    local ports=""
    if command -v sshd >/dev/null 2>&1; then
      ports=$(sshd -T -C user=root,host="$(hostname)",addr=127.0.0.1 2>/dev/null \
              | awk '/^port /{print $2}' | sort -u | paste -sd, -)
    fi
    if [ -z "${ports:-}" ] && [ -r /etc/ssh/sshd_config ]; then
      ports=$(awk '/^\s*Port\s+[0-9]+/ {print $2}' /etc/ssh/sshd_config | sort -u | paste -sd, -)
    fi
    if [ -z "${ports:-}" ]; then
      if command -v ss >/dev/null 2>&1; then
        ports=$(ss -tuln | awk '/sshd/ { if (match($0, /:([0-9]+)/, a)) print a[1] }' | sort -u | paste -sd, -)
      elif command -v netstat >/dev/null 2>&1; then
        ports=$(netstat -tulnp 2>/dev/null | awk '/sshd/ { if (match($0, /:([0-9]+)/, a)) print a[1] }' | sort -u | paste -sd, -)
      fi
    fi
    [ -z "${ports:-}" ] && ports="22"
    echo "$ports"
  }

  _extract_port_from_file() {
    # Args: <file> <section>
    # Returns the LAST 'port =' seen in that section of the file (ignores comments/whitespace)
    local file="$1" section="$2"
    awk -v want="[$section]" '
      function ltrim(s){sub(/^[ \t]+/,"",s);return s}
      function rmcmt(s){sub(/[ \t]*#.*$/,"",s);sub(/[ \t]*;.*$/,"",s);return s}
      BEGIN{ins=0;last=""}
      {
        line=$0
        gsub(/\r$/,"",line)
        line=rmcmt(line)
        line=ltrim(line)
        if(line=="") next
        if(line ~ /^\[/){
          ins = (tolower(line) == tolower(want))
          next
        }
        if(ins && line ~ /^port[ \t]*=/){
          sub(/^port[ \t]*=[ \t]*/,"",line)
          last=line
        }
      }
      END{ if(last!="") print last }
    ' "$file" 2>/dev/null
  }

  _get_f2b_ports_for_jail() {
    # Effective precedence: jail.conf -> jail.d/*.conf (sorted) -> jail.local (last wins)
    local jail="$1"
    local default_port="" jail_port="" v f

    # 1) jail.conf
    f="/etc/fail2ban/jail.conf"
    [ -f "$f" ] && {
      v="$(_extract_port_from_file "$f" "DEFAULT")";   [ -n "$v" ] && default_port="$v"
      v="$(_extract_port_from_file "$f" "$jail")";     [ -n "$v" ] && jail_port="$v"
    }

    # 2) jail.d/*.conf (sorted)
    if [ -d /etc/fail2ban/jail.d ]; then
      for f in $(ls -1 /etc/fail2ban/jail.d/*.conf 2>/dev/null | sort); do
        v="$(_extract_port_from_file "$f" "DEFAULT")"; [ -n "$v" ] && default_port="$v"
        v="$(_extract_port_from_file "$f" "$jail")";   [ -n "$v" ] && jail_port="$v"
      done
    fi

    # 3) jail.local (highest precedence)
    f="/etc/fail2ban/jail.local"
    [ -f "$f" ] && {
      v="$(_extract_port_from_file "$f" "DEFAULT")";   [ -n "$v" ] && default_port="$v"
      v="$(_extract_port_from_file "$f" "$jail")";     [ -n "$v" ] && jail_port="$v"
    }

    # Choose jail-specific if set; else DEFAULT; else literal "ssh"
    local raw="${jail_port:-$default_port}"
    [ -z "$raw" ] && raw="ssh"

    # Resolve names -> numbers where possible
    _resolve_tokens_to_ports "$raw"
  }

  _detect_fb_log() {
    # pick fail2ban log source
    if [ -f /var/log/fail2ban.log ]; then
      echo "/var/log/fail2ban.log"
    elif [ -f /var/log/fail2ban/fail2ban.log ]; then
      echo "/var/log/fail2ban/fail2ban.log"
    else
      echo ""  # use journalctl fallback
    fi
  }

  # ---------- main ----------
  local ssh_ports fb_ports
  ssh_ports="$(_detect_ssh_ports)"
  echo "SSH Port(s): $ssh_ports"

  fb_ports="$(_get_f2b_ports_for_jail "sshd")"
  [ -z "$fb_ports" ] && fb_ports="ssh"
  echo "Fail2Ban Port(s): $fb_ports"

  # mismatch warning (simple string compare; normalize spaces)
  if [ -n "$ssh_ports" ] && [ -n "$fb_ports" ]; then
    if [ "$(echo "$ssh_ports" | tr -d ' ')" != "$(echo "$fb_ports" | tr -d ' ')" ]; then
      echo "⚠️  WARNING: SSH is on $ssh_ports but Fail2Ban is monitoring $fb_ports"
    fi
  fi

  # service status
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    echo "Fail2Ban Service: active (running)"
  else
    echo "Fail2Ban Service: inactive (stopped)"
  fi

  # jail summary (counts + banned list)
  if command -v fail2ban-client >/dev/null 2>&1; then
    echo
    echo "--- Jail: sshd ---"
    sudo fail2ban-client status sshd 2>/dev/null \
      | grep -E "Currently failed|Total failed|Currently banned|Total banned|Banned IP list" \
      || echo "sshd jail not found or disabled."
  else
    echo
    echo "fail2ban-client not found."
  fi

  # recent attacker IPs (top offenders)
  echo
  echo "--- Recent offender IPs (last ~1000 lines) ---"
  local logf offenders
  logf="$(_detect_fb_log)"
  if [ -n "$logf" ] && [ -r "$logf" ]; then
    offenders=$(tail -n 1000 "$logf" \
      | awk '/sshd/ && /Found/ { for (i=1;i<=NF;i++) if ($i ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/) print $i }' \
      | sort | uniq -c | sort -nr | head -n 15)
    if [ -n "$offenders" ]; then
      echo "$offenders" | sed 's/^/  /'
    else
      echo "  (no recent matches)"
    fi
  elif command -v journalctl >/dev/null 2>&1; then
    offenders=$(journalctl -u fail2ban --since "24 hours ago" --no-pager 2>/dev/null \
      | awk '/sshd/ && /Found/ { for (i=1;i<=NF;i++) if ($i ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/) print $i }' \
      | sort | uniq -c | sort -nr | head -n 15)
    if [ -n "$offenders" ]; then
      echo "$offenders" | sed 's/^/  /'
    else
      echo "  (no recent matches)"
    fi
  else
    echo "  (no log source found)"
  fi

  echo "=============================="
}



# Docker Sub Menu
docker_management() {
    while true; do
        clear
        echo "▶ Docker Management"
        echo "------------------------"
        echo "1. Install/Update Docker Environment"
        echo "2. View Docker Global Status"
        echo "3. Clean Up Unused Docker Resources"
        echo "4. Uninstall Docker Environment"
        echo "------------------------"
        echo "0. Return to Main Menu"
        echo "------------------------"
        read -p "Enter your choice: " sub_choice

        case $sub_choice in
            1)
                clear
                install_docker
                ;;
            2)
                clear
                echo "Docker Version"
                docker -v
                docker-compose --version

                echo ""
                echo "Docker Image List"
                docker image ls
                echo ""
                echo "Docker Container List"
                docker ps -a
                echo ""
                echo "Docker Volume List"
                docker volume ls
                echo ""
                echo "Docker Network List"
                docker network ls
                echo ""
                read -p "Press any key to continue..." key
                ;;
            3)
                clear
                read -p "$(echo -e "Are you sure you want to clean up unused images, containers, networks, and volumes? (Y/N): ")" choice
                case "$choice" in
                    [Yy])
                        docker system prune -af --volumes
                        echo "Cleaned up unused Docker resources."
                        ;;
                    [Nn])
                        ;;
                    *)
                        echo "Invalid choice, please enter Y or N."
                        ;;
                esac
                ;;
            4)
                clear
                read -p "$(echo -e "Are you sure you want to uninstall the Docker environment? (Y/N): ")" choice
                case "$choice" in
                    [Yy])
                        docker rm $(docker ps -a -q)
                        docker rmi $(docker images -q)
                        docker network prune
                        remove_docker
                        echo "Docker environment uninstalled."
                        ;;
                    [Nn])
                        ;;
                    *)
                        echo "Invalid choice, please enter Y or N."
                        ;;
                esac
                ;;
            0)
                break  # Exit the loop, return to the main menu
                ;;
            *)
                echo "Invalid input!"
                ;;
        esac
    done
}

install_docker() {
    clear
    echo "Installing Docker..."
    DIR="/root/containers/"
    if [ ! -d "$DIR" ]; then
        mkdir -p "$DIR"
        echo "Directory $DIR created."
    else
        cd "$DIR"
        echo "Changed directory to $DIR."
    fi

    # Install Docker using the convenience script
    curl -fsSL https://get.docker.com | sh
    
    # Start and enable the Docker service
    systemctl start docker
    systemctl enable docker
    
    # Download and install Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    echo "Docker installation completed."
}

remove_docker() {
    echo "Uninstalling Docker..."
    # Stop Docker services
    systemctl stop docker

    # Remove Docker packages
    apt-get purge -y docker-ce docker-ce-cli containerd.io

    # Remove Docker Compose
    rm -f /usr/local/bin/docker-compose

    # Remove Docker data
    rm -rf /var/lib/docker
    rm -rf /var/lib/containerd

    # Clean up residual configuration files
    apt-get autoremove -y
    apt-get clean

    echo "Docker has been successfully uninstalled."
}

# WARP Management Submenu
warp_management() {
    while true; do
        clear
        echo "▶ WARP Management"
        echo "------------------------"
        echo "1. Install WARP Client"
        echo "2. Check WARP Status"
        echo "3. Enable WARP"
        echo "4. Disable WARP"
        echo "5. Uninstall WARP Client"
        echo "------------------------"
        echo "0. Return to Main Menu"
        echo "------------------------"
        read -p "Enter your choice: " sub_choice

        case $sub_choice in
            1)
                install_warp
                ;;
            2)
                check_warp_status
                ;;
            3)
                enable_warp
                ;;
            4)
                disable_warp
                ;;
            5)
                uninstall_warp
                ;;
            0)
                break  # Exit the loop, return to the main menu
                ;;
            *)
                echo "Invalid input!"
                ;;
        esac
    done
}

install_warp() {
    clear
    echo "Installing WARP Client..."
    
    # Add the Cloudflare WARP repository and GPG key
    apt update
    apt install -y curl gnupg
    curl -s https://pkg.cloudflareclient.com/pubkey.gpg | apt-key add -
    echo "deb [arch=amd64] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list

    # Update package list and install WARP
    apt update
    apt install -y cloudflare-warp

    # Register and connect WARP client
    warp-cli register
    warp-cli connect

    echo "WARP Client installation completed."
}

check_warp_status() {
    clear
    echo "Checking WARP Status..."
    
    # Display WARP client status
    warp-cli status
    echo ""
}

enable_warp() {
    clear
    echo "Enabling WARP..."
    
    # Connect to WARP
    warp-cli connect
    echo "WARP has been enabled."
}

disable_warp() {
    clear
    echo "Disabling WARP..."
    
    # Disconnect from WARP
    warp-cli disconnect
    echo "WARP has been disabled."
}

uninstall_warp() {
    clear
    echo "Uninstalling WARP Client..."

    # Disconnect and remove the WARP client
    warp-cli disconnect
    apt remove -y cloudflare-warp
    apt autoremove -y
    rm -f /etc/apt/sources.list.d/cloudflare-client.list

    echo "WARP Client has been uninstalled."
}

# Sub-menu for wgcf
wgcf() {
    while true; do
        echo "Choose an option:"
        echo "1. Generate configuration"
        echo "2. Check status"
        echo "3. Trace"
        echo "4. Check reserved ID"
        echo "0. Back to main menu"

        read -p "Enter your choice: " choice

        case $choice in
            1)
                generate_wgcf_config
                ;;
            2)
                check_status
                ;;
            3)
                trace
                ;;
            4)
                check_reserved
                ;;
            0)
                break
                ;;
            *)
                echo "Invalid choice. Please enter a valid option."
                ;;
        esac
    done
}

# Function to generate configuration
generate_wgcf_config() {
    apt install jq -y
    wgcf_file="/root/warpgen/wgcf"

    # Check if wgcf file already exists
    if [ ! -e "$wgcf_file" ]; then
        # Check the system's architecture
        mkdir -p /root/warpgen/
        arch=$(uname -m)

        if [ "$arch" == "x86_64" ]; then
            echo "Downloading for AMD..."
            wget -O "$wgcf_file" https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_amd64
        elif [ "$arch" == "aarch64" ]; then
            echo "Downloading for ARM..."
            wget -O "$wgcf_file" https://github.com/ViRb3/wgcf/releases/download/v2.2.19/wgcf_2.2.19_linux_arm64
        else
            echo "Unsupported architecture: $arch"
            exit 1
        fi

        chmod +x "$wgcf_file"  # Make the downloaded file executable
    else
        echo "wgcf file already exists. Skipping download."
    fi
    cd /root/warpgen/

    rm -fr wgcf-account.toml
    ./wgcf register
    sleep 2 # Adding a delay of 2 seconds
    cat wgcf-account.toml # Displaying the contents of wgcf-account.toml
    read -p "Enter the new WGCF license key: " new_key
    WGCF_LICENSE_KEY="$new_key" ./wgcf update
    sleep 2
    cat wgcf-account.toml # Displaying the contents of wgcf-account.toml
    # Fetching device_id and access_token from wgcf-account.toml
    device_id=$(grep -oP "device_id = '\K[^']+" wgcf-account.toml)
    access_token=$(grep -oP "access_token = '\K[^']+" wgcf-account.toml)

    # Fetching information using curl command
    response=$(curl --request GET "https://api.cloudflareclient.com/v0a2158/reg/$device_id" \
        --silent \
        --location \
        --header 'User-Agent: okhttp/3.12.1' \
        --header 'CF-Client-Version: a-6.10-2158' \
        --header 'Content-Type: application/json' \
        --header "Authorization: Bearer $access_token")

    # Extracting client_id from the response
    client_id=$(echo "$response" | jq -r '.config.client_id')

    # Converting client_id into array format [14, 116, 111]
    client_id_array=$(echo "$client_id" | base64 -d | xxd -p | fold -w2 | while read HEX; do printf '%d ' "0x${HEX}"; done | awk '{print "["$1", "$2", "$3"]"}')

    ./wgcf generate

    sleep 2 # Adding a delay of 2 seconds

    # Fetching PrivateKey and Address from wgcf-profile.conf
    private_key=$(grep -oP "PrivateKey = \K[^ ]+" wgcf-profile.conf)
    addresses=$(grep -oP "Address = \K[^ ]+" wgcf-profile.conf)

    # Extracting individual IPv4 and IPv6 addresses
    ipv4=$(echo "$addresses" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+')
    ipv6=$(echo "$addresses" | grep -Eo '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/[0-9]+')
    # Creating wireguard.json file
    cat > wireguard.json <<EOF
{
    "tag": "xray-wg-warp",
    "protocol": "wireguard",
    "settings": {
        "secretKey": "$private_key",
        "address": [
            "$ipv4",
            "$ipv6"
        ],
        "peers": [
            {
                "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "allowedIPs": [
                    "0.0.0.0/0",
                    "::/0"
                ],
                "endpoint": "162.159.193.10:2408"
            }
        ],
        "reserved": $client_id_array
    }
}
EOF
    sleep 2
    echo "wireguard.json file created successfully."
    cat wireguard.json
}

# Function to check status
check_status() {
    cd && cd /root/warpgen/
    ./wgcf status
}

# Function to trace
trace() {
    cd && cd /root/warpgen/
    ./wgcf trace
}

check_reserved() {
    apt install jq -y
    cd && cd /root/warpgen/
    cat wgcf-account.toml # Displaying the contents of wgcf-account.toml
    # Fetching device_id and access_token from wgcf-account.toml
    device_id=$(grep -oP "device_id = '\K[^']+" wgcf-account.toml)
    access_token=$(grep -oP "access_token = '\K[^']+" wgcf-account.toml)

    # Fetching information using curl command
    response=$(curl --request GET "https://api.cloudflareclient.com/v0a2158/reg/$device_id" \
        --silent \
        --location \
        --header 'User-Agent: okhttp/3.12.1' \
        --header 'CF-Client-Version: a-6.10-2158' \
        --header 'Content-Type: application/json' \
        --header "Authorization: Bearer $access_token")

    # Extracting client_id from the response
    client_id=$(echo "$response" | jq -r '.config.client_id')

    # Converting client_id into array format [14, 116, 111]
    client_id_array=$(echo "$client_id" | base64 -d | xxd -p | fold -w2 | while read HEX; do printf '%d ' "0x${HEX}"; done | awk '{print "["$1", "$2", "$3"]"}')
    echo $client_id_array
}

update_script() {
    echo "Updating the script..."

    # Download the updated script
    updated_script_url="https://raw.githubusercontent.com/pandaaxi/shellscript/main/panda.sh"
    if curl -fsSL -o panda.sh "$updated_script_url"; then
        chmod +x panda.sh
        echo "Script updated successfully."
        exit 0  # Exit after updating to avoid any issues
    else
        echo "Failed to update the script. Please check the provided link."
    fi
}

# bbr management
bbr_management() {
    # Install necessary dependencies if needed
    if ! command -v wget &> /dev/null; then
        apt-get update && apt-get install -y wget
    fi

    # Download and execute tcpx.sh script
    wget -4 --no-check-certificate -O tcpx.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh
    chmod +x tcpx.sh
    ./tcpx.sh

    # Clean up after running the script
    rm -f tcpx.sh

    echo "BBR Management completed. Returning to Main Menu."
    read -p "Press any key to continue..." key
}

# Function for Realm Management
realm_management() {
    # Install necessary dependencies if needed
    if ! command -v wget &> /dev/null; then
        apt-get update && apt-get install -y wget
    fi

    # Check if realm.sh is already available
    if [ ! -f realm.sh ]; then
        # Download and execute realm.sh script
        wget -4 --no-check-certificate -O realm.sh https://github.com/pandaaxi/mine/raw/refs/heads/main/realm.sh
        chmod +x realm.sh
    fi

    ./realm.sh

    echo "Realm Management completed. Returning to Main Menu."
    read -p "Press any key to continue..." key
}

main_menu