#!/bin/bash
#=============================================================================
# V2Ray(Xray) + WebSocket + TLS + Nginx + Cloudflare 一键部署脚本
# 适用系统: Debian 10+/Ubuntu 20.04+/CentOS 7+
#=============================================================================

set -e

# ---- 颜色输出 ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}==>${NC} ${BLUE}$*${NC}"; }

# ---- 参数检查 ----
DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
    echo "用法: bash install.sh <你的域名>"
    echo "示例: bash install.sh v2ray.example.com"
    exit 1
fi

# 生成随机路径和 UUID
WS_PATH="/ws-$(head -c 8 /dev/urandom | md5sum | head -c 8)"
UUID=$(cat /proc/sys/kernel/random/uuid)

step "开始部署 V2Ray(Xray)+WebSocket+TLS+Nginx"
info "域名:   $DOMAIN"
info "WS路径: $WS_PATH"

# ---- 1. 系统更新 & 基础工具 ----
step "1/7 系统更新 & 安装基础工具"
if [ -f /etc/debian_version ]; then
    apt update -y && apt upgrade -y
    apt install -y curl wget unzip nginx socat ufw
elif [ -f /etc/redhat-release ]; then
    yum update -y
    yum install -y epel-release
    yum install -y curl wget unzip nginx socat firewalld
    systemctl enable firewalld --now
fi

# ---- 2. 安装 Xray ----
step "2/7 安装 Xray"
bash -c "$(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install || {
    # 备用：手动安装
    warn "官方脚本失败，尝试手动安装..."
    XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d'"' -f4)
    [ -z "$XRAY_VER" ] && XRAY_VER="v25.1.1"
    ARCH=$(uname -m)
    case $ARCH in x86_64) XARCH="64";; aarch64) XARCH="arm64-v8a";; *) XARCH="64";; esac
    URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-${XARCH}.zip"
    mkdir -p /usr/local/xray && cd /usr/local/xray
    curl -sLO "$URL" && unzip -oq "Xray-linux-${XARCH}.zip" && rm -f "Xray-linux-${XARCH}.zip"
    chmod +x xray

    # 创建 systemd 服务
    cat > /etc/systemd/system/xray.service << 'SVC'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/xray/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC
    mkdir -p /usr/local/etc/xray /var/log/xray
}

# ---- 3. 配置 Xray ----
step "3/7 配置 Xray"
mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json << XRAYCONF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$WS_PATH"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ]
}
XRAYCONF

# ---- 4. 配置 Nginx ----
step "4/7 配置 Nginx"

# 先停掉可能占 80 的服务
systemctl stop nginx 2>/dev/null || true

cat > /etc/nginx/conf.d/${DOMAIN}.conf << NGINXCONF
server {
    listen 80;
    server_name ${DOMAIN};
    root /var/www/html;

    # 用于 Cloudflare 代理时获取真实 IP
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;

    # 伪装站点 - 返回一个正常的 404 页面
    location / {
        return 404;
    }

    # ACME 验证路径
    location ~ ^/.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # WebSocket 代理
    location ${WS_PATH} {
        if (\$http_upgrade = "websocket") {
            proxy_pass http://127.0.0.1:10086;
        }
        proxy_pass http://127.0.0.1:10086;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
NGINXCONF

# 删除默认站点
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true

# 启动 Nginx
systemctl enable nginx
systemctl start nginx

# ---- 5. 获取 TLS 证书 (acme.sh) ----
step "5/7 申请 TLS 证书"

# 先确保 80 端口可用
sleep 2
curl -sI "http://${DOMAIN}" > /dev/null 2>&1 || warn "80端口暂时无法访问，继续尝试申请证书..."

# 安装 acme.sh
if [ ! -d ~/.acme.sh ]; then
    curl -s https://get.acme.sh | sh -s email=admin@${DOMAIN}
fi

# 申请证书
~/.acme.sh/acme.sh --issue -d "${DOMAIN}" -w /var/www/html --debug 2>&1 | tail -5 || {
    warn "HTTP 验证失败，尝试 DNS 验证方式..."
    warn "请手动到 Cloudflare 添加 TXT 记录后重新运行证书申请"
}

# 安装证书
CERT_DIR="/etc/ssl/${DOMAIN}"
mkdir -p "$CERT_DIR"
~/.acme.sh/acme.sh --install-cert -d "${DOMAIN}" \
    --key-file       "${CERT_DIR}/privkey.pem" \
    --fullchain-file "${CERT_DIR}/fullchain.pem" \
    --reloadcmd      "systemctl restart nginx"

# ---- 6. Nginx 开启 TLS ----
step "6/7 Nginx 开启 TLS"

# 覆盖配置，添加 443 端口
cat > /etc/nginx/conf.d/${DOMAIN}.conf << NGINXTLS
# HTTP -> HTTPS 重定向
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # Cloudflare 真实 IP
    set_real_ip_from 173.245.48.0/20;    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;   set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;     set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;      set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;      set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;     set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;     set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;     set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;

    # WebSocket 代理
    location ${WS_PATH} {
        if (\$http_upgrade = "websocket") {
            proxy_pass http://127.0.0.1:10086;
        }
        proxy_pass http://127.0.0.1:10086;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # 伪装站点 - 返回空页面
    location / {
        root /var/www/html;
        index index.html;
        try_files \$uri \$uri/ =404;
    }

    # ACME 续期
    location ~ ^/.well-known/acme-challenge/ {
        root /var/www/html;
    }
}
NGINXTLS

# 创建伪装首页
mkdir -p /var/www/html
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title>
<style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f2f5}
h1{color:#1a1a2e}</style></head><body><h1>Welcome to Nginx</h1></body></html>
EOF

nginx -t && systemctl restart nginx

# ---- 7. 防火墙 & 启动 Xray ----
step "7/7 防火墙配置 & 启动服务"

if command -v ufw &>/dev/null; then
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    echo "y" | ufw enable 2>/dev/null || true
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
fi

systemctl daemon-reload
systemctl enable xray
systemctl restart xray
sleep 2

# ---- 最终状态检查 ----
step "部署完成！状态检查"

echo ""
echo "============================================"
echo "  Nginx  状态: $(systemctl is-active nginx)"
echo "  Xray   状态: $(systemctl is-active xray)"
echo "  证书路径:    ${CERT_DIR}/"
echo "============================================"
echo ""

# ---- 生成客户端配置 ----
CLIENT_JSON=$(cat << CLIENT
{
  "v": "2",
  "ps": "${DOMAIN}",
  "add": "${DOMAIN}",
  "port": "443",
  "id": "${UUID}",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "${DOMAIN}",
  "path": "${WS_PATH}",
  "tls": "tls",
  "sni": "${DOMAIN}",
  "alpn": "",
  "fp": "chrome"
}
CLIENT
)

# Base64 编码 (VMess 链接格式)
VMESS_LINK="vmess://$(echo -n "$CLIENT_JSON" | base64 -w 0 2>/dev/null || echo -n "$CLIENT_JSON" | base64)"

echo "============== 客户端连接信息 =============="
echo ""
echo "  协议:    vmess"
echo "  地址:    ${DOMAIN}"
echo "  端口:    443"
echo "  UUID:    ${UUID}"
echo "  安全:    tls"
echo "  传输:    ws"
echo "  路径:    ${WS_PATH}"
echo "  SNI:     ${DOMAIN}"
echo "  alterId: 0"
echo ""
echo "  VMess 链接:"
echo "  ${VMESS_LINK}"
echo ""
echo "============================================"
echo ""
info "请将以上信息填入 V2Ray/Xray 客户端。"
info "建议 Cloudflare SSL/TLS 模式设为 Full (strict)。"
warn "如果证书申请失败，请确保域名已解析到本机IP，然后手动运行："
warn "  ~/.acme.sh/acme.sh --issue -d ${DOMAIN} -w /var/www/html"

# 保存信息到文件
cat > /root/v2ray-info.txt << SAVEINFO
域名:    ${DOMAIN}
端口:    443
UUID:    ${UUID}
路径:    ${WS_PATH}
传输:    ws
安全:    tls
SNI:     ${DOMAIN}
alterId: 0

VMess链接:
${VMESS_LINK}
SAVEINFO

info "连接信息已保存至 /root/v2ray-info.txt"
