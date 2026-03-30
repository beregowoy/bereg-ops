#!/bin/bash
set -euo pipefail

# === Проверка прав root ===
if [[ $EUID -ne 0 ]]; then
   echo "❌ Ошибка: Этот скрипт должен запускаться от root"
   echo "Используйте: sudo ./node_slfsteal_setup.sh"
   exit 1
fi

echo "=== Node Setup Script ==="
echo "Этот скрипт создаст пользователя, настроит SSH, Docker и Remnanode."
echo "Для настройки Selfsteal запустите отдельно: ./selfsteal_setup.sh"
echo

# === Ввод данных пользователя ===
read -p "Введите имя пользователя: " USERNAME
read -s -p "Введите пароль для пользователя: " USER_PASSWORD
echo
read -s -p "Введите пароль для root: " ROOT_PASSWORD
echo
read -p "Введите порт SSH (например 5125): " SSH_PORT
read -p "Вставьте публичный SSH ключ: " PUB_KEY
echo

# === Проверка, что порт свободен ===
if ss -tulpn | grep -q ":$SSH_PORT "; then
  echo "❌ Ошибка: порт $SSH_PORT уже используется. Выберите другой порт."
  exit 1
fi

# === Обновление системы и установка пакетов ===
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y || true
apt-get install -y sudo nano wget curl cron sqlite3 file ufw

# === Создание пользователя ===
if id -u "$USERNAME" >/dev/null 2>&1; then
  echo "Пользователь $USERNAME уже существует. Обновляем права..."
  usermod -s /bin/bash "$USERNAME"
  usermod -aG sudo "$USERNAME" || true
else
  useradd -m -s /bin/bash "$USERNAME"
  usermod -aG sudo "$USERNAME"
fi
echo "${USERNAME}:${USER_PASSWORD}" | chpasswd

# === Установка пароля root ===
echo "root:${ROOT_PASSWORD}" | chpasswd

# === Настройка SSH ===
mkdir -p /home/"$USERNAME"/.ssh
chmod 700 /home/"$USERNAME"/.ssh
chown -R "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh

AUTH_FILE="/home/$USERNAME/.ssh/authorized_keys"
touch "$AUTH_FILE"
grep -qxF "$PUB_KEY" "$AUTH_FILE" || echo "$PUB_KEY" >> "$AUTH_FILE"
# Только root может изменять authorized_keys для безопасности
chmod 644 "$AUTH_FILE"
chown root:"$USERNAME" "$AUTH_FILE"

mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
EOF

# Проверяем конфиг и перезапускаем SSH
mkdir -p /run/sshd
chmod 755 /run/sshd
sshd -t
echo "Перезапуск SSH..."
systemctl restart ssh || systemctl restart sshd || true
echo "✅ SSH перезапущен."

# === Root доступ настроен ===
# Пароль root установлен выше, SSH доступ к root заблокирован

# === Настройка брандмауэра UFW ===
ufw --force reset || true
ufw allow "$SSH_PORT"/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow 2222/tcp || true
ufw default deny incoming || true
ufw default allow outgoing || true
echo "y" | ufw enable || true
systemctl enable ufw --now || true

# === Установка Docker ===
echo "=== Установка Docker ==="
curl -fsSL https://get.docker.com | sh
systemctl enable docker --now || true

# === Remnanode ===
echo "=== Настройка Remnanode ==="
mkdir -p /opt/remnanode && cd /opt/remnanode
echo "Вставьте конфиг docker-compose.yml в редактор (nano). Сохраните: Ctrl+O, Enter, Ctrl+X"
read -p "Нажмите Enter, когда откроется редактор..." _
nano docker-compose.yml
echo "Запуск Remnanode..."
docker compose up -d
echo "✅ Remnanode запущен. Логи: docker compose logs -f -t (в /opt/remnanode)"
cd - >/dev/null

# === Завершение ===
IP_ADDR=$(hostname -I | awk '{print $1}')
echo
echo "===================================="
echo "✅ Настройка ноды завершена!"
echo "Подключайтесь по SSH:"
echo "ssh -p $SSH_PORT $USERNAME@$IP_ADDR"
echo "===================================="
echo
echo "Открытые порты на сервере:"
ufw status numbered | grep "ALLOW"
echo "===================================="
echo
echo "Для настройки Selfsteal запустите:"
echo "sudo ./selfsteal_setup.sh"
echo "===================================="
