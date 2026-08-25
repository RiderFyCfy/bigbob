#!/bin/bash
set -e

echo "=== 1. Настройка DNS хоста и отключение IPv6 ==="
cat << 'RESOLV' > /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1 1.0.0.1 8.8.8.8
FallbackDNS=8.8.4.4
Domains=~.
DNSSEC=no
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
Cache=yes
RESOLV

cat << 'SYSCTL' > /etc/sysctl.d/99-disable-ipv6.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
SYSCTL

sysctl -p /etc/sysctl.d/99-disable-ipv6.conf
systemctl restart systemd-resolved 2>/dev/null || true

echo "=== 2. Установка и запуск Cloudflare WARP ==="
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null || true
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
apt-get update -y && apt-get install -y cloudflare-warp

# Регистрация WARP (с обработкой существующей регистрации)
warp-cli --accept-tos registration new 2>/dev/null || true
warp-cli --accept-tos mode proxy 2>/dev/null || warp-cli --accept-tos set-mode proxy 2>/dev/null || true
warp-cli --accept-tos proxy port 40000 2>/dev/null || warp-cli --accept-tos set-proxy-port 40000 2>/dev/null || true
warp-cli --accept-tos connect 2>/dev/null || true
systemctl enable --now warp-svc 2>/dev/null || true

echo "=== 3. Обновление базы данных 3X-UI ==="
python3 - << 'PYEOF'
import sqlite3, json, os

db_paths = ['/etc/x-ui/x-ui.db', '/usr/local/x-ui/x-ui.db']
db_path = None
for p in db_paths:
    if os.path.exists(p):
        db_path = p
        break

if not db_path:
    print("❌ База данных x-ui.db не найдена. Убедитесь, что 3X-UI установлен.")
    exit(1)

print(f"Используем базу данных: {db_path}")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# 1. Включение Sniffing на всех inbounds
try:
    cursor.execute("SELECT id FROM inbounds")
    for (ib_id,) in cursor.fetchall():
        sniff = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False})
        cursor.execute("UPDATE inbounds SET sniffing=? WHERE id=?", (sniff, ib_id))
except Exception as e:
    print(f"Предупреждение при обновлении inbounds: {e}")

# 2. Получение или создание базового шаблона Xray
cursor.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'")
row = cursor.fetchone()

default_template = {
    "inbounds": [{"listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1"}, "tag": "api"}],
    "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}, {"tag": "blocked", "protocol": "blackhole", "settings": {}}],
    "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}], "domainStrategy": "IPIfNonMatch"},
    "log": {"access": "none", "dnsLog": False, "error": "", "loglevel": "warning", "maskAddress": ""},
    "policy": {"system": {"statsInboundDownlink": True, "statsInboundUplink": True, "statsOutboundDownlink": False, "statsOutboundUplink": False}, "levels": {"0": {"statsUserDownlink": True, "statsUserUplink": True}}},
    "api": {"services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"], "tag": "api"},
    "metrics": {"listen": "127.0.0.1:11111", "tag": "metrics_out"},
    "stats": {}
}

if row and row[0]:
    try:
        template = json.loads(row[0])
    except:
        template = default_template
else:
    template = default_template

# Настройка DNS блока
template['dns'] = {
    'servers': ['1.1.1.1', '8.8.8.8', 'https://1.1.1.1/dns-query'],
    'queryStrategy': 'UseIPv4'
}

# Outbounds
warp_outbound = {
    'tag': 'warp',
    'protocol': 'socks',
    'settings': {'servers': [{'address': '127.0.0.1', 'port': 40000}]}
}
outbounds = [ob for ob in template.get('outbounds', []) if ob.get('tag') != 'warp']
for ob in outbounds:
    if ob.get('tag') == 'direct' and ob.get('protocol') == 'freedom':
        if 'settings' not in ob: ob['settings'] = {}
        ob['settings']['domainStrategy'] = 'UseIPv4'
outbounds.append(warp_outbound)
template['outbounds'] = outbounds

# Routing
domains = [
    "geosite:google", "geosite:openai", "geosite:anthropic",
    "domain:google.com", "domain:youtube.com", "domain:googlevideo.com",
    "domain:googleusercontent.com", "domain:gstatic.com", "domain:googleapis.com",
    "domain:gvt1.com", "domain:1e100.net", "domain:gemini.google.com",
    "domain:bard.google.com", "domain:aistudio.google.com", "domain:makeruite.google.com",
    "domain:generativelanguage.googleapis.com", "domain:alkalimakersuite-pa.clients6.google.com",
    "domain:proactivebackend-pa.googleapis.com", "domain:cloudconfig.googleapis.com",
    "domain:firebaseinstallations.googleapis.com", "domain:deepmind.google",
    "domain:deepmind.com", "domain:antigravity.google", "domain:antigravity.dev",
    "domain:antigravity.com", "domain:antigravity.ai", "domain:antigravity-ide.google",
    "domain:antigravity-dev.google", "domain:chatgpt.com", "domain:openai.com",
    "domain:claude.ai", "domain:anthropic.com"
]

google_rule = {'type': 'field', 'domain': domains, 'ip': ['geoip:google'], 'outboundTag': 'warp'}
quic_rule = {'type': 'field', 'network': 'udp', 'port': '443', 'outboundTag': 'blocked'}
dns_port_rule = {'type': 'field', 'port': '53,853', 'outboundTag': 'direct'}
dns_proto_rule = {'type': 'field', 'protocol': ['dns'], 'outboundTag': 'direct'}

rules = template.get('routing', {}).get('rules', [])
rules = [r for r in rules if r.get('outboundTag') != 'warp' and not (r.get('port') == '443' and r.get('network') == 'udp')]

api_rules = [r for r in rules if 'api' in r.get('inboundTag', []) or r.get('outboundTag') == 'api']
other_rules = [r for r in rules if r not in api_rules]

new_rules = list(api_rules) + [google_rule, dns_port_rule, dns_proto_rule] + list(other_rules) + [quic_rule]
template['routing'] = {'domainStrategy': 'IPIfNonMatch', 'rules': new_rules}

# Запись в базу данных (insert or replace)
val_str = json.dumps(template)
cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('xrayTemplateConfig', ?)", (val_str,))
conn.commit()
conn.close()
print("Шаблон Xray успешно обновлен в базе данных.")
PYEOF

echo "=== 4. Перезапуск 3X-UI ==="
systemctl restart x-ui 2>/dev/null || true

echo "=== 5. Проверка статуса ==="
sleep 2
systemctl is-active --quiet x-ui && echo "✅ 3X-UI / Xray успешно запущен и настроен!" || echo "❌ Ошибка запуска x-ui"
systemctl is-active --quiet warp-svc && echo "✅ Cloudflare WARP активен!" || echo "❌ Ошибка warp-svc"
