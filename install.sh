#!/bin/bash
# 
# sing-box + VLESS + HTTPUpgrade + Cloudflare Tunnel + ECH + Caddy 一键安装脚本
# 基于博客文章: https://blog.chaos.run/dreams/sing-box-vless-httpupgrade-cloudflare-tunnel-ech/
# 适用系统: Debian 12/13, Ubuntu 24.04+
#

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BLUE}==>${NC} ${BLUE}$1${NC}\n"; }

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行，请使用 sudo 执行。"
        exit 1
    fi
}

# 检查系统兼容性
check_system() {
    if [[ -f /etc/debian_version ]]; then
        log_info "检测到 Debian/Ubuntu 系统"
    else
        log_error "此脚本仅支持 Debian/Ubuntu 系统"
        exit 1
    fi
}

# 用户输入收集
collect_input() {
    clear
    echo "=========================================="
    echo "  sing-box 一键安装脚本 v1.0"
    echo "  基于 VLESS + HTTPUpgrade + CF Tunnel"
    echo "=========================================="
    echo ""
    echo -e "${YELLOW}请准备好以下信息：${NC}"
    echo "  1. Cloudflare 账号（已托管域名）"
    echo "  2. Cloudflare API Token（需 Tunnel:Edit 和 DNS:Edit 权限）"
    echo "  3. 要使用的域名（如 example.com）"
    echo "  4. 代理子域名（如 cdn.example.com）"
    echo "  5. 静态伪装网站源码（可选）"
    echo ""

    read -p "请输入代理服务域名 (如 cdn.example.com): " PROXY_DOMAIN
    read -p "请输入根域名 (Cloudflare 托管的域名, 如 example.com): " ROOT_DOMAIN
    read -sp "请输入 Cloudflare API Token: " CF_API_TOKEN
    echo ""
    read -p "请输入伪装静态网站的 GitHub 仓库 URL (留空跳过): " WEBSITE_REPO

    # 提取子域名部分
    SUBDOMAIN=$(echo "$PROXY_DOMAIN" | sed "s/\.${ROOT_DOMAIN}$//")

    # 生成随机隐藏路径
    HIDDEN_PATH=$(openssl rand -hex 12)
    log_info "生成的随机隐藏路径: ${HIDDEN_PATH}"

    # 生成 UUID
    log_info "正在生成 UUID..."
    UUID=$(sing-box generate uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    log_info "生成的 UUID: ${UUID}"

    # 确认信息
    echo ""
    echo -e "${GREEN}请确认以下信息:${NC}"
    echo "  代理域名: ${PROXY_DOMAIN}"
    echo "  根域名: ${ROOT_DOMAIN}"
    echo "  子域名: ${SUBDOMAIN}"
    echo "  隐藏路径: ${HIDDEN_PATH}"
    echo "  UUID: ${UUID}"
    echo ""
    read -p "确认继续安装? (y/N): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_error "安装已取消"
        exit 0
    fi
}

# 安装基础工具
install_base_tools() {
    log_step "步骤 1/6: 更新系统并安装基础工具"
    apt update && apt upgrade -y
    apt install -y curl wget vim unzip openssl ca-certificates gnupg2 debian-archive-keyring
    log_info "基础工具安装完成"
}

# 安装 cloudflared
install_cloudflared() {
    log_step "步骤 2/6: 安装 Cloudflared"

    mkdir -p --mode=0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | tee /etc/apt/sources.list.d/cloudflared.list
    apt update
    apt install -y cloudflared

    log_info "Cloudflared 安装完成"
}

# 配置 Cloudflare Tunnel (命令行方式)
configure_cloudflare_tunnel() {
    log_step "配置 Cloudflare Tunnel"

    # 登录 Cloudflare
    log_info "正在登录 Cloudflare..."
    echo "$CF_API_TOKEN" | cloudflared tunnel login --token "$CF_API_TOKEN" 2>/dev/null || {
        log_warn "Token 登录失败，尝试手动登录..."
        cloudflared tunnel login
    }

    # 创建 Tunnel
    TUNNEL_NAME="sing-box-tunnel-$(openssl rand -hex 4)"
    log_info "创建 Tunnel: ${TUNNEL_NAME}"
    cloudflared tunnel create "$TUNNEL_NAME"

    # 获取 Tunnel ID
    TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
    log_info "Tunnel ID: ${TUNNEL_ID}"

    # 创建配置文件
    mkdir -p ~/.cloudflared
    cat > ~/.cloudflared/config.yml << EOF
tunnel: $TUNNEL_ID
credentials-file: /root/.cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: $PROXY_DOMAIN
    service: http://localhost:8080
  - service: http_status:404
EOF

    # 配置 DNS 记录
    log_info "配置 DNS 记录: ${PROXY_DOMAIN}"
    cloudflared tunnel route dns "$TUNNEL_ID" "$PROXY_DOMAIN"

    # 安装为系统服务
    cloudflared service install

    log_info "Cloudflare Tunnel 配置完成"
    log_warn "请在 Cloudflare Dashboard 确认 Tunnel 状态"
}

# 安装 Caddy
install_caddy() {
    log_step "步骤 3/6: 安装 Caddy"

    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list
    apt update
    apt install -y caddy

    log_info "Caddy 安装完成"
}

# 配置伪装网站
configure_website() {
    log_step "步骤 4/6: 配置伪装网站"

    WEBSITE_DIR="/var/www/html"
    mkdir -p "$WEBSITE_DIR"

    if [[ -n "$WEBSITE_REPO" ]]; then
        log_info "从 GitHub 下载伪装网站..."
        apt install -y git
        git clone "$WEBSITE_REPO" /tmp/website
        cp -rf /tmp/website/* "$WEBSITE_DIR/" 2>/dev/null || true
        rm -rf /tmp/website
    else
        log_info "创建默认伪装页面..."
        cat > "$WEBSITE_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
        p { color: #666; }
    </style>
</head>
<body>
    <h1>正在加载中...</h1>
    <p>请稍后再试</p>
</body>
</html>
EOF
    fi

    chown -R www-data:www-data "$WEBSITE_DIR"
    log_info "伪装网站配置完成"
}

# 配置 Caddy
configure_caddy() {
    log_step "步骤 5/6: 配置 Caddy 反向代理"

    cat > /etc/caddy/Caddyfile << EOF
$PROXY_DOMAIN {
    # 日志记录
    log {
        output file /var/log/caddy/access.log
        level INFO
    }

    # 根路径返回伪装网站
    root * /var/www/html
    file_server

    # 隐藏路径代理到 sing-box
    handle /$HIDDEN_PATH/* {
        reverse_proxy 127.0.0.1:8443
    }

    # 自定义 404 页面
    handle_errors {
        rewrite * /404.html
        file_server
    }
}
EOF

    # 创建日志目录并设置权限
    mkdir -p /var/log/caddy
    chown -R caddy:caddy /var/log/caddy

    # 验证配置
    caddy validate --config /etc/caddy/Caddyfile

    systemctl enable caddy
    systemctl restart caddy

    log_info "Caddy 配置完成"
}

# 安装 sing-box
install_singbox() {
    log_step "安装 Sing-box"

    mkdir -p /etc/apt/keyrings
    curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
    chmod a+r /etc/apt/keyrings/sagernet.asc

    cat > /etc/apt/sources.list.d/sagernet.sources << EOF
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF

    apt update
    apt install -y sing-box

    log_info "Sing-box 安装完成"
}

# 配置 sing-box
configure_singbox() {
    log_step "步骤 6/6: 配置 Sing-box"

    cat > /etc/sing-box/config.json << EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "https",
        "tag": "local",
        "server": "1.1.1.1"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [
        {
          "name": "user",
          "uuid": "$UUID"
        }
      ],
      "transport": {
        "type": "httpupgrade",
        "path": "/$HIDDEN_PATH"
      },
      "multiplex": {
        "enabled": true,
        "padding": true
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "domain_resolver": "local"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "ip_is_private": true,
        "action": "reject"
      },
      {
        "protocol": "bittorrent",
        "action": "reject"
      }
    ],
    "final": "direct"
  }
}
EOF

    # 验证配置
    sing-box check -c /etc/sing-box/config.json

    systemctl enable sing-box
    systemctl restart sing-box

    log_info "Sing-box 配置完成"
}

# 显示客户端配置
show_client_config() {
    log_step "✨ 安装完成！✨"

    echo ""
    echo "=========================================="
    echo -e "${GREEN}服务端已成功部署${NC}"
    echo "=========================================="
    echo ""

    # 生成客户端配置 JSON
    cat > /root/client-config.json << EOF
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "cf-main",
      "server": "$PROXY_DOMAIN",
      "server_port": 443,
      "uuid": "$UUID",
      "tls": {
        "enabled": true,
        "server_name": "$PROXY_DOMAIN",
        "alpn": ["http/1.1"],
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "ech": {
          "enabled": true
        }
      },
      "transport": {
        "type": "httpupgrade",
        "host": "$PROXY_DOMAIN",
        "path": "/$HIDDEN_PATH"
      },
      "multiplex": {
        "enabled": true,
        "protocol": "h2mux",
        "max_streams": 16,
        "padding": true
      }
    }
  ]
}
EOF

    echo -e "${YELLOW}客户端配置信息:${NC}"
    echo "  代理域名: ${PROXY_DOMAIN}"
    echo "  UUID: ${UUID}"
    echo "  隐藏路径: ${HIDDEN_PATH}"
    echo ""
    echo -e "${YELLOW}客户端配置文件已保存至: /root/client-config.json${NC}"
    echo ""

    # 生成客户端链接
    ENCODED_PATH=$(echo -n "/$HIDDEN_PATH" | jq -sRr @uri)
    CLIENT_LINK="vless://${UUID}@${PROXY_DOMAIN}:443?encryption=none&security=tls&sni=${PROXY_DOMAIN}&fp=chrome&alpn=http/1.1&type=httpupgrade&host=${PROXY_DOMAIN}&path=${ENCODED_PATH}#Cloudflare-Tunnel-VLESS"
    echo -e "${YELLOW}客户端链接 (可在 sing-box GUI 中导入):${NC}"
    echo "${CLIENT_LINK}"
    echo ""

    echo -e "${YELLOW}服务状态检查命令:${NC}"
    echo "  sudo systemctl status cloudflared"
    echo "  sudo systemctl status caddy"
    echo "  sudo systemctl status sing-box"
    echo ""
    echo -e "${YELLOW}验证 ECH 是否可用:${NC}"
    echo "  dig ${PROXY_DOMAIN} HTTPS @1.1.1.1"
    echo ""

    log_warn "重要提醒:"
    echo "  1. 请在 Cloudflare Dashboard 确认 Tunnel 状态为 Active"
    echo "  2. 确保 Cloudflare SSL/TLS 加密模式设为 Full (strict)"
    echo "  3. 确认 Edge Certificates 中 ECH 已启用"
    echo "  4. 客户端 DNS 需支持 HTTPS RR 查询（建议使用 1.1.1.1 或 8.8.8.8）"
}

# 主函数
main() {
    check_root
    check_system
    collect_input

    # 依次执行安装步骤
    install_base_tools
    install_cloudflared
    install_caddy
    install_singbox
    configure_cloudflare_tunnel
    configure_website
    configure_caddy
    configure_singbox

    # 重启所有服务
    log_info "重启所有服务..."
    systemctl restart cloudflared
    systemctl restart caddy
    systemctl restart sing-box

    # 显示客户端配置
    show_client_config

    log_info "脚本执行完毕！"
}

# 运行主函数
main "$@"
