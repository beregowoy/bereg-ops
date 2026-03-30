# bereg-ops — Claude Instructions

## Ops Server Connection

```bash
ssh -p 5125 -i ~/.ssh/bereg_ops_mavl ops@62.133.62.27
```

| Параметр | Значение |
|----------|----------|
| IP       | 62.133.62.27 |
| Port     | 5125 |
| User     | ops |
| Key      | ~/.ssh/bereg_ops_mavl |

Запуск команд на ops:
```bash
ssh -o StrictHostKeyChecking=no -p 5125 -i ~/.ssh/bereg_ops_mavl ops@62.133.62.27 "команда"
```

## Ключевые пути на ops-сервере

| Путь | Назначение |
|------|------------|
| `/opt/bereg-ops/` | Ansible + скрипты |
| `/opt/monitoring_server/` | Prometheus + Grafana |
| `/opt/whitebox/` | Whitebox VPN probe |
| `/opt/whitebox/.env` | Токены для whitebox |

## Remnawave Panel

- URL: `https://rem.bereg.bond`
- API token: в `/opt/whitebox/.env` на ops-сервере

## Node Config Profiles

| Тип | Profile | UUID |
|-----|---------|------|
| standard | RLT_RAW_SELF | 52edd661-aed1-48ee-ab9e-47a784060f54 |
| ru-full  | RU_FULL_SLF  | 45f37423-88fa-47c7-9426-0ca2fa0955f1 |
| bridge   | BRIDGE       | 16aa91e1-d872-4a2b-a973-4b397169be76 |

## Добавление новой ноды

Пользователь даёт данные в формате:
```
Новая нода:
IP: 1.2.3.4
Имя: DE-05
Тип: standard
Домен: de05.bopen.bond
Пароль root: xxx
```

Скрипт: `/opt/bereg-ops/add-node.py`

## SSH ключ ansible на нодах

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHL9z2FJS8RNAui84L4JzToLtJgOE+f3JJtKVzA23pg7 ansible@bereg-vpn-ops
```
