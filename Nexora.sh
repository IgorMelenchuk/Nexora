#!/bin/bash

# Цвета для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Файл логов
LOG_FILE="/var/log/Nexora.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Функция обновления системы
update_system() {
    echo -e "${GREEN}[1/17] Обновление системы...${NC}"
    sudo apt update && sudo apt upgrade -y
    sudo apt autoremove -y
}

# Функция оптимизации сетевых параметров
optimize_network() {
    echo -e "${GREEN}[2/17] Оптимизация сетевых параметров...${NC}"
    cat <<EOF | sudo tee /etc/sysctl.conf > /dev/null
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_congestion_control = bbr
EOF
    sudo sysctl -p
    echo -e "${GREEN}BBR активирован.${NC}"
}

# Функция настройки swap или Zram
setup_memory_optimization() {
    echo -e "${GREEN}[3/17] Настройка управления памятью (Swap/Zram)...${NC}"
    TOTAL_RAM=$(free -m | awk '/Mem:/ {print $2}')
    
    if [ "$TOTAL_RAM" -lt 2048 ]; then
        echo -e "${YELLOW}RAM < 2GB, создаем Swap-файл...${NC}"
        sudo fallocate -l 2G /swapfile
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile
        sudo swapon /swapfile
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        echo -e "${GREEN}Swap-файл создан.${NC}"
    else
        echo -e "${YELLOW}RAM >= 2GB, настраиваем Zram...${NC}"
        sudo apt install -y zram-tools
        echo "ALGO=lz4" | sudo tee /etc/default/zramswap
        sudo systemctl enable --now zramswap
        echo -e "${GREEN}Zram активирован.${NC}"
    fi
}

# Функция установки 3x-ui с автонастройкой
install_3x_ui() {
    echo -e "${GREEN}[4/17] Установка 3x-ui...${NC}"
    bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)
    echo -e "${GREEN}3x-ui установлен.${NC}"

    # Запрос домена и email для TLS-сертификата
    read -p "Введите доменное имя (example.com): " DOMAIN
    read -p "Введите email для сертификата (admin@example.com): " EMAIL

    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        echo -e "${RED}Домен или email не указаны. Генерация сертификата пропущена.${NC}"
    else
        echo -e "${GREEN}Генерация TLS-сертификата через 3x-ui...${NC}"
        sudo x-ui cert create -d "$DOMAIN" -e "$EMAIL"
        echo -e "${GREEN}TLS-сертификат успешно создан.${NC}"
    fi

    # Автонастройка 3x-ui для максимальной производительности
    echo -e "${GREEN}Настройка 3x-ui для максимальной производительности...${NC}"
    UUID=$(cat /proc/sys/kernel/random/uuid)
    CONFIG_PATH="/etc/xray/config.json"
    cat <<EOF | sudo tee $CONFIG_PATH > /dev/null
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/root/cert.crt",
              "keyFile": "/root/private.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    sudo systemctl restart xray
    echo -e "${GREEN}3x-ui настроен. UUID: ${YELLOW}$UUID${NC}"
}

# Функция отключения ненужных служб
disable_unnecessary_services() {
    echo -e "${GREEN}[5/17] Отключение ненужных служб...${NC}"
    sudo systemctl disable --now apache2 mysql postfix snapd cups.service avahi-daemon.service bluetooth.service >/dev/null 2>&1
    echo -e "${GREEN}Лишние службы отключены.${NC}"
}

# Функция усиления безопасности (защита SSH, UFW, Fail2Ban)
enhance_security() {
    echo -e "${GREEN}[6/17] Усиление безопасности...${NC}"
    sudo ufw allow 22/tcp
    sudo ufw allow 443/tcp
    sudo ufw enable
    sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl restart ssh
    sudo apt install -y fail2ban
    sudo systemctl enable --now fail2ban
    echo -e "${GREEN}SSH, UFW и Fail2Ban настроены.${NC}"
}

# Функция установки инструментов мониторинга
setup_monitoring() {
    echo -e "${GREEN}[7/17] Установка инструментов мониторинга...${NC}"
    sudo apt install -y htop iftop net-tools
    echo -e "${GREEN}Мониторинг установлен.${NC}"
}

# Функция оптимизации загрузки системы
optimize_boot() {
    echo -e "${GREEN}[8/17] Оптимизация загрузки системы...${NC}"
    sudo journalctl --vacuum-size=100M
    echo -e "${GREEN}Логи очищены, загрузка ускорена.${NC}"
}

# Функция оптимизации работы CPU
optimize_cpu() {
    echo -e "${GREEN}[9/17] Оптимизация CPU...${NC}"
    echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
    echo -e "${GREEN}CPU настроен на производительный режим.${NC}"
}

# Функция настройки системных лимитов
setup_limits() {
    echo -e "${GREEN}[10/17] Настройка системных лимитов...${NC}"
    cat <<EOF | sudo tee /etc/security/limits.conf > /dev/null
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF
    echo -e "${GREEN}Лимиты настроены.${NC}"
}

# Функция оптимизации работы с диском
optimize_disk_io() {
    echo -e "${GREEN}[11/17] Оптимизация работы с диском...${NC}"
    DISK_SCHEDULER=$(cat /sys/block/sda/queue/scheduler)
    if [[ "$DISK_SCHEDULER" == *"mq-deadline"* ]]; then
        echo "mq-deadline" | sudo tee /sys/block/sda/queue/scheduler
    elif [[ "$DISK_SCHEDULER" == *"none"* ]]; then
        echo "none" | sudo tee /sys/block/sda/queue/scheduler
    fi
    echo -e "${GREEN}Дисковый планировщик настроен.${NC}"
}

# Функция настройки автоматических обновлений
setup_automatic_updates() {
    echo -e "${GREEN}[12/17] Настройка автоматических обновлений...${NC}"
    sudo apt install -y unattended-upgrades
    sudo dpkg-reconfigure -plow unattended-upgrades
    echo -e "${GREEN}Автоматические обновления настроены.${NC}"
}

# Функция резервного копирования
setup_backup() {
    echo -e "${GREEN}[13/17] Настройка резервного копирования...${NC}"
    sudo apt install -y rsync
    BACKUP_DIR="/backup"
    sudo mkdir -p $BACKUP_DIR
    cat <<EOF | sudo tee /etc/cron.daily/backup > /dev/null
#!/bin/bash
rsync -av --delete /etc /usr/local/etc /var/log $BACKUP_DIR/
EOF
    sudo chmod +x /etc/cron.daily/backup
    echo -e "${GREEN}Резервное копирование настроено.${NC}"
}

# Функция очистки временных файлов
clean_temp_files() {
    echo -e "${GREEN}[14/17] Очистка временных файлов...${NC}"
    sudo rm -rf /tmp/*
    sudo rm -rf /var/tmp/*
    echo -e "${GREEN}Временные файлы очищены.${NC}"
}

# Функция отправки уведомлений через Telegram
send_notification() {
    echo -e "${GREEN}[15/17] Отправка уведомления...${NC}"
    read -p "Введите ваш Telegram Bot Token: " BOT_TOKEN
    read -p "Введите ваш Chat ID: " CHAT_ID

    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        echo -e "${RED}Bot Token или Chat ID не указаны. Уведомление пропущено.${NC}"
    else
        MESSAGE="Оптимизация VPS завершена! Проверьте логи: ${LOG_FILE}"
        curl -s -X POST https://api.telegram.org/bot$BOT_TOKEN/sendMessage -d chat_id=$CHAT_ID -d text="$MESSAGE"
        echo -e "${GREEN}Уведомление отправлено.${NC}"
    fi
}

# Функция проверки статуса сервисов
check_services() {
    echo -e "${GREEN}[16/17] Проверка статуса сервисов...${NC}"
    SERVICES=("xray" "nginx" "ufw" "fail2ban")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet $service; then
            echo -e "${GREEN}$service активен.${NC}"
        else
            echo -e "${RED}$service неактивен.${NC}"
        fi
    done
}

# Основной процесс
echo -e "${YELLOW}=== Начало оптимизации VPS ===${NC}"
update_system
optimize_network
setup_memory_optimization
install_3x_ui
disable_unnecessary_services
enhance_security
setup_monitoring
optimize_boot
optimize_cpu
setup_limits
optimize_disk_io
setup_automatic_updates
setup_backup
clean_temp_files
send_notification
check_services
echo -e "${YELLOW}=== Оптимизация завершена! ===${NC}"