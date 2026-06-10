#!/bin/bash
set -e

KEYS=$(xray x25519 2>/dev/null)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $NF}')
SHORT_ID=$(head -c 4 /dev/urandom | hexdump -e '"%02x"')
REALITY_PORT=8443
DEST_SITE="www.microsoft.com"
OLD_UUID="6d9e32de-326a-41c8-847e-31ba6ca650b1"

echo "[INFO] Private:  $PRIVATE_KEY"
echo "[INFO] Public:   $PUBLIC_KEY"
echo "[INFO] ShortId:  $SHORT_ID"
echo ""

cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.vmess.bak 2>/dev/null || true

cat > /usr/local/etc/xray/config.json << XRAYEOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": "OLD_UUID_PLACEHOLDER", "alterId": 0}]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/ws-c9e2c837"}
      }
    },
    {
      "port": REALITY_PORT_PLACEHOLDER,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "OLD_UUID_PLACEHOLDER", "flow": "xtls-rprx-vision"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "DEST_SITE_PLACEHOLDER:443",
          "xver": 0,
          "serverNames": ["DEST_SITE_PLACEHOLDER"],
          "privateKey": "PRIVATE_KEY_PLACEHOLDER",
          "shortIds": ["SHORT_ID_PLACEHOLDER"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],
  "outbounds": [
    {"protocol": "freedom", "settings": {}},
    {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
  ]
}
XRAYEOF

sed -i "s/OLD_UUID_PLACEHOLDER/${OLD_UUID}/g" /usr/local/etc/xray/config.json
sed -i "s/REALITY_PORT_PLACEHOLDER/${REALITY_PORT}/g" /usr/local/etc/xray/config.json
sed -i "s/DEST_SITE_PLACEHOLDER/${DEST_SITE}/g" /usr/local/etc/xray/config.json
sed -i "s/PRIVATE_KEY_PLACEHOLDER/${PRIVATE_KEY}/g" /usr/local/etc/xray/config.json
sed -i "s/SHORT_ID_PLACEHOLDER/${SHORT_ID}/g" /usr/local/etc/xray/config.json

ufw allow ${REALITY_PORT}/tcp 2>/dev/null || true
iptables -I INPUT -p tcp --dport ${REALITY_PORT} -j ACCEPT 2>/dev/null || true

systemctl restart xray

# 生成 VLESS 链接
REMARK=$(echo "akaklk-Reality" | sed 's/ /%20/g')
VLESS_LINK="vless://${OLD_UUID}@107.173.155.90:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DEST_SITE}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${REMARK}"

echo ""
echo "=========================================="
echo "  Reality Node Ready"
echo "=========================================="
echo "  Protocol: vless"
echo "  Address:  107.173.155.90"
echo "  Port:     ${REALITY_PORT}"
echo "  UUID:     ${OLD_UUID}"
echo "  Flow:     xtls-rprx-vision"
echo "  Security: reality"
echo "  SNI:      ${DEST_SITE}"
echo "  Finger:   chrome"
echo "  Public:   ${PUBLIC_KEY}"
echo "  ShortId:  ${SHORT_ID}"
echo ""
echo "  VLESS Link:"
echo "  ${VLESS_LINK}"
echo ""
echo "  VMess (CF) still on port 443"
echo "=========================================="

# 保存信息
cat > /root/reality-info.txt << SAVEINFO
Protocol: vless
Address:  107.173.155.90
Port:     ${REALITY_PORT}
UUID:     ${OLD_UUID}
Flow:     xtls-rprx-vision
Security: reality
SNI:      ${DEST_SITE}
Finger:   chrome
Public:   ${PUBLIC_KEY}
ShortId:  ${SHORT_ID}

VLESS Link:
${VLESS_LINK}
SAVEINFO
