#!/bin/bash
set -euo pipefail

# === Проверка прав root ===
if [[ $EUID -ne 0 ]]; then
   echo "❌ Ошибка: Этот скрипт должен запускаться от root"
   echo "Используйте: sudo ./selfsteal_setup.sh"
   exit 1
fi

echo "=== Selfsteal (Caddy) Setup Script ==="
echo "Этот скрипт настроит Selfsteal (Caddy) для работы с Remnanode."
echo

# === Ввод данных ===
read -p "Введите домен для Selfsteal (SELF_STEAL_DOMAIN): " SELF_STEAL_DOMAIN
SELF_STEAL_PORT=9443
echo

# === Открытие порта в UFW ===
echo "Открытие порта $SELF_STEAL_PORT в UFW..."
ufw allow "${SELF_STEAL_PORT}"/tcp || true

# === Статическая страница с авторизацией (/opt/html) — создаём до запуска Caddy ===
echo "=== Создание страницы авторизации ==="
mkdir -p /opt/html
cat > /opt/html/index.html << 'HTML_EOF'
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Selfsteal — Вход</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      color: #e8e8e8;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }
    .card {
      width: 100%;
      max-width: 380px;
      padding: 2rem;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    h1 {
      margin: 0 0 1.5rem;
      font-size: 1.5rem;
      font-weight: 600;
      text-align: center;
    }
    label {
      display: block;
      margin-bottom: 0.35rem;
      font-size: 0.9rem;
      color: #b0b0b0;
    }
    input {
      width: 100%;
      padding: 0.75rem 1rem;
      margin-bottom: 1rem;
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 8px;
      background: rgba(0,0,0,0.2);
      color: #fff;
      font-size: 1rem;
    }
    input::placeholder { color: #666; }
    input:focus {
      outline: none;
      border-color: #4a9eff;
      box-shadow: 0 0 0 2px rgba(74,158,255,0.2);
    }
    button {
      width: 100%;
      padding: 0.85rem;
      margin-top: 0.5rem;
      border: none;
      border-radius: 8px;
      background: linear-gradient(135deg, #4a9eff, #357abd);
      color: #fff;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.9; }
    button:active { opacity: 0.8; }
    .hint {
      margin-top: 1rem;
      font-size: 0.85rem;
      color: #888;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>Selfsteal</h1>
    <form id="login" method="post" action="#" onsubmit="return handleLogin(event)">
      <label for="user">Логин</label>
      <input id="user" name="user" type="text" placeholder="Введите логин" autocomplete="username" required>
      <label for="pass">Пароль</label>
      <input id="pass" name="pass" type="password" placeholder="Введите пароль" autocomplete="current-password" required>
      <button type="submit">Войти</button>
    </form>
    <p class="hint">Страница авторизации. Настройте проверку на своей стороне.</p>
  </div>
  <script>
    function handleLogin(e) {
      e.preventDefault();
      var u = document.getElementById('user').value;
      var p = document.getElementById('pass').value;
      alert('Форма авторизации (логин: ' + u + '). Для реальной проверки подключите бэкенд.');
      return false;
    }
  </script>
</body>
</html>
HTML_EOF
echo "✅ Страница авторизации создана: /opt/html/index.html"

# === Selfsteal (Caddy) ===
echo "=== Настройка Selfsteal (Caddy) ==="
mkdir -p /opt/selfsteel && cd /opt/selfsteel

cat > Caddyfile << 'CADDYFILE_EOF'
{
    https_port {$SELF_STEAL_PORT}
    default_bind 127.0.0.1
    servers {
        listener_wrappers {
            proxy_protocol {
                allow 127.0.0.1/32
            }
            tls
        }
    }
    auto_https disable_redirects
}

http://{$SELF_STEAL_DOMAIN} {
    bind 0.0.0.0
    redir https://{$SELF_STEAL_DOMAIN}{uri} permanent
}

https://{$SELF_STEAL_DOMAIN} {
    root * /var/www/html
    try_files {path} /index.html
    file_server

}

:{$SELF_STEAL_PORT} {
    tls internal
    respond 204
}

:80 {
    bind 0.0.0.0
    respond 204
}
CADDYFILE_EOF

cat > .env << ENV_EOF
SELF_STEAL_DOMAIN=$SELF_STEAL_DOMAIN
SELF_STEAL_PORT=$SELF_STEAL_PORT
ENV_EOF

cat > docker-compose.yml << 'COMPOSE_EOF'
services:
  caddy:
    image: caddy:latest
    container_name: caddy-remnawave
    restart: unless-stopped
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ../html:/var/www/html
      - ./logs:/var/log/caddy
      - caddy_data_selfsteal:/data
      - caddy_config_selfsteal:/config
    env_file:
      - .env
    network_mode: "host"

volumes:
  caddy_data_selfsteal:
  caddy_config_selfsteal:
COMPOSE_EOF

mkdir -p logs
echo "Запуск Caddy (Selfsteal)..."
docker compose up -d
echo "✅ Caddy запущен. Логи: docker compose logs -f -t (в /opt/selfsteel)"
cd - >/dev/null

# === Завершение ===
echo
echo "===================================="
echo "✅ Selfsteal настроен!"
echo "Домен: $SELF_STEAL_DOMAIN"
echo "Порт: $SELF_STEAL_PORT"
echo "===================================="
