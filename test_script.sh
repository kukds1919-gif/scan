#!/bin/bash

set -e

# 색상 정의
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RED="\e[31m"
BOLD="\e[1m"
RESET="\e[0m"

print_section() {
    echo -e "\n${BOLD}${CYAN}========== $1 ==========${RESET}"
}

print_step() {
    echo -e "${GREEN}[*]${RESET} $1"
}

print_section "Step 1: Updating & Installing Packages"
sudo apt install -y apache2 mariadb-server samba openssh-server xrdp nmap net-tools

# ufw 설치 여부 확인
if ! command -v ufw >/dev/null 2>&1; then
    print_step "Installing ufw firewall..."
    sudo apt install -y ufw
fi

print_section "Step 2: Enabling Firewall"
sudo ufw enable || true

print_section "Step 3: Allowing Required Ports"
for port in 22 80 443 445 3306 3389; do
    print_step "Allowing TCP port $port"
    sudo ufw allow $port/tcp
done

print_section "Step 4: Starting & Enabling Services"
for svc in apache2 mysql smbd ssh xrdp; do
    print_step "Starting and enabling service: $svc"
    sudo systemctl start $svc
    sudo systemctl enable $svc
done

print_section "Step 5: Firewall Status"
sudo ufw status numbered

print_section "Step 6: Services Status"
for svc in apache2 mysql smbd ssh xrdp; do
    status=$(systemctl is-active $svc || echo 'inactive')
    if [[ "$status" == "active" ]]; then
        echo -e " - $svc: ${GREEN}$status${RESET}"
    else
        echo -e " - $svc: ${RED}$status${RESET}"
    fi
done

print_section "Step 7: Listening TCP Ports (neststat -tulp)"
sudo netstat -tuln | grep LISTEN

print_section "Step 8: Nmap Scan (All Ports)"
nmap -p- localhost

print_section "Script Completed"
