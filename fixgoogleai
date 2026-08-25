bash <(cat << 'EOF'
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
systemctl restart systemd-resolved

echo "=== 2. Установка и запуск Cloudflare WARP ==="
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
apt-get update -y && apt-get install -y cloudflare-warp

warp-cli --accept-tos registration new || warp-cli --accept-tos register || true
warp-cli --accept-tos mode proxy || warp-cli --accept-tos set-mode proxy
warp-cli --accept-tos proxy port 40000 || warp-cli --accept-tos set-proxy-port 40000
warp-cli --accept-tos connect
systemctl enable --now warp-svc

echo "=== 3. Обновление базы данных 3X-UI ==="
python3 - << 'PYEOF'
import sqlite3, json, subprocess

DB_PATH = '/etc/x-ui/x-ui.db'
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# 1. Включение Sniffing на всех inbounds
cursor.execute("SELECT id FROM inbounds")
for (ib_id,) in cursor.fetchall():
    sniff = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False})
    cursor.execute("UPDATE inbounds SET sniffing=? WHERE id=?", (sniff, ib_id))

# 2. Обновление шаблона Xray
cursor.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'")
row = cursor.fetchone()
template = json.loads(row[0])

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

cursor.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (json.dumps(template),))
conn.commit()
conn.close()
PYEOF

echo "=== 4. Перезапуск 3X-UI ==="
systemctl restart x-ui

echo "=== 5. Проверка статуса ==="
sleep 2
systemctl is-active --quiet x-ui && echo "✅ 3X-UI / Xray успешно запущен и настроен!" || echo "❌ Ошибка запуска x-ui"
systemctl is-active --quiet warp-svc && echo "✅ Cloudflare WARP активен!" || echo "❌ Ошибка warp-svc"
EOF
)
