#!/bin/bash
# 
# sing-box + VLESS + HTTPUpgrade + Cloudflare Tunnel + ECH + Caddy 一键安装脚本
# 增强特性：自动状态检查 + 友好错误处理 + 健康报告
# 基于博客：https://blog.chaos.run/dreams/sing-box-vless-httpupgrade-cloudflare-tunnel-ech/
# 适用系统：Debian 12/13, Ubuntu 24.04+
#

set -e  # 遇到致命错误自动退出，但我们会用更细粒度的控制

# ======================== 颜色与日志函数 ========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BLUE}==>${NC} ${BLUE}$1${NC}\n"; }

# 错误处理：显示错误后等待用户选择是否继续
error_handler() {
    log_error "$1"
    echo ""
    read -p "是否继续尝试后续步骤？(y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "安装已中止，请根据上面的错误信息手动排查。"
        exit 1
    fi
}

# 检查服务是否活跃，并给出建议
check_service() {
    local service_name=$1
    local friendly_name=$2
    if systemctl is-active --quiet "$service_name"; then
        log_info "$friendly_name 服务运行正常 ✔"
        return 0
    else
        log_error "$friendly_name 服务未运行 ✘"
        echo "  请手动检查: systemctl status $service_name"
        echo "  查看日志: journalctl -u $service_name -n 20"
        return 1
    fi
}

# 检查端口是否监听
check_port() {
    local port=$1
    if ss -tlnp | grep -q ":$port "; then
        log_info "端口 $port 已被监听 ✔"
        return 0
    else
        log_warn "端口 $port 未被监听，可能服务未正确绑定"
        return 1
    fi
}

# 检查 HTTP 响应 (本地测试)
test_http() {
    local url=$1
    local expected_code=$2
    local description=$3
    local curl_output
    curl_output=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 "$url" 2>/dev/null)
    if [[ "$curl_output" == "$expected_code" ]]; then
        log_info "$description 访问成功 (HTTP $curl_output) ✔"
        return 0
    else
        log_error "$description 访问失败 (HTTP $curl_output，期望 $expected_code) ✘"
        return 1
    fi
}

# ======================== 安装前检查 ========================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行，请使用 sudo 执行。"
        exit 1
    fi
}

check_system() {
    if [[ -f /etc/debian_version ]]; then
        log_info "检测到 Debian/Ubuntu 系统 ✔"
    else
        log_error "此脚本仅支持 Debian/Ubuntu 系统"
        exit 1
    fi
}

# ======================== 用户输入 ========================
collect_input() {
    clear
    echo "=========================================="
    echo "  sing-box 一键安装脚本 (小白友好版)"
    echo "  自动状态检查 + 错误修复建议"
    echo "=========================================="
    echo ""
    read -p "请输入代理服务域名 (如 cdn.example.com): " PROXY_DOMAIN
    read -p "请输入根域名 (Cloudflare 托管的域名, 如 example.com): " ROOT_DOMAIN
    read -sp "请输入 Cloudflare API Token (需 DNS:Edit + Tunnel:Edit 权限): " CF_API_TOKEN
    echo ""
    read -p "请输入伪装静态网站的 GitHub 仓库 URL (留空将使用默认页面): " WEBSITE_REPO

    SUBDOMAIN=$(echo "$PROXY_DOMAIN" | sed "s/\.${ROOT_DOMAIN}$//")
    HIDDEN_PATH=$(openssl rand -hex 12)
    log_info "自动生成的随机路径: ${HIDDEN_PATH}"

    echo ""
    echo -e "${GREEN}请确认以下信息:${NC}"
    echo "  代理域名: ${PROXY_DOMAIN}"
    echo "  根域名: ${ROOT_DOMAIN}"
    echo "  随机路径: ${HIDDEN_PATH}"
    echo ""
    read -p "确认继续安装? (y/N): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_error "安装已取消"
        exit 0
    fi
}

# ======================== 安装步骤 ========================
install_base_tools() {
    log_step "1/7 更新系统并安装基础工具"
    apt update && apt upgrade -y
    apt install -y curl wget vim unzip openssl ca-certificates gnupg2 debian-archive-keyring git jq
    log_info "基础工具安装完成"
}

install_cloudflared() {
    log_step "2/7 安装 Cloudflared"
    mkdir -p --mode=0755 /usr/share/keyrings
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" | tee /etc/apt/sources.list.d/cloudflared.list
    apt update
    apt install -y cloudflared
    log_info "Cloudflared 安装完成"
}

install_caddy() {
    log_step "3/7 安装 Caddy"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod o+r /etc/apt/sources.list.d/caddy-stable.list
    apt update
    apt install -y caddy
    log_info "Caddy 安装完成"
}

install_singbox() {
    log_step "4/7 安装 Sing-box"
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

# ======================== 配置与验证 ========================
configure_cloudflare_tunnel() {
    log_step "5/7 配置 Cloudflare Tunnel"

    TUNNEL_NAME="sing-box-tunnel-$(openssl rand -hex 4)"
    CRED_FILE="/root/.cloudflared/${TUNNEL_NAME}.json"
    log_info "创建 Tunnel: ${TUNNEL_NAME}"

    if ! cloudflared tunnel create "$TUNNEL_NAME" --credentials-file "$CRED_FILE"; then
        error_handler "Tunnel 创建失败，请检查 API Token 权限和网络连通性。"
        return 1
    fi

    TUNNEL_ID=$(jq -r '.TunnelID' "$CRED_FILE")
    log_info "Tunnel ID: ${TUNNEL_ID}"

    mkdir -p ~/.cloudflared
    cat > ~/.cloudflared/config.yml << EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CRED_FILE}
ingress:
  - hostname: ${PROXY_DOMAIN}
    service: http://localhost:8080
  - service: http_status:404
EOF

    log_info "配置 DNS 记录: ${PROXY_DOMAIN}"
    cloudflared tunnel route dns "$TUNNEL_ID" "$PROXY_DOMAIN"

    cloudflared service install
    systemctl restart cloudflared

    # 等待几秒让 tunnel 上线
    sleep 5
    if cloudflared tunnel info "$TUNNEL_ID" >/dev/null 2>&1; then
        log_info "Cloudflare Tunnel 已在线 ✔"
    else
        log_warn "Cloudflare Tunnel 可能尚未上线，请在 Dashboard 手动检查"
    fi
}

configure_website() {
    log_step "6/7 配置伪装网站"
    WEBSITE_DIR="/var/www/html"
    mkdir -p "$WEBSITE_DIR"

    if [[ -n "$WEBSITE_REPO" ]]; then
        log_info "从 GitHub 下载伪装网站..."
        git clone "$WEBSITE_REPO" /tmp/website || {
            error_handler "Git clone 失败，将使用默认页面"
            WEBSITE_REPO=""
        }
        if [[ -z "$WEBSITE_REPO" ]]; then
            # 继续使用默认
            cat > "$WEBSITE_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html><body><h1>It works!</h1></body></html>
EOF
        else
            cp -rf /tmp/website/* "$WEBSITE_DIR/" 2>/dev/null
            rm -rf /tmp/website
        fi
    else
        cat > "$WEBSITE_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html><body><h1>Welcome to CDN</h1></body></html>
EOF
    fi
    chown -R www-data:www-data "$WEBSITE_DIR"
    log_info "伪装网站配置完成"
}

configure_caddy() {
    log_step "配置 Caddy 反向代理"

    cat > /etc/caddy/Caddyfile << EOF
${PROXY_DOMAIN} {
    root * /var/www/html
    file_server
    handle /${HIDDEN_PATH}/* {
        reverse_proxy 127.0.0.1:8443
    }
}
EOF

    caddy validate --config /etc/caddy/Caddyfile
    systemctl enable caddy
    systemctl restart caddy

    # 等待 Caddy 启动
    sleep 3
    if check_service caddy "Caddy" && check_port 80 && check_port 443; then
        log_info "Caddy 基础运行正常"
    else
        error_handler "Caddy 端口监听失败，可能被其他程序占用或配置错误"
    fi

    # 本地测试伪装网站
    test_http "http://localhost/" "200" "伪装网站根路径 (http)"
    # 测试隐藏路径是否能被 Caddy 代理到 sing-box (此时 sing-box 尚未配置，预期返回 502)
    # 我们暂且只测根路径
}

configure_singbox() {
    log_step "7/7 配置 Sing-box"

    UUID=$(sing-box generate uuid)
    log_info "生成的 UUID: ${UUID}"

    cat > /etc/sing-box/config.json << EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [ { "uuid": "$UUID" } ],
      "transport": {
        "type": "httpupgrade",
        "host": "$PROXY_DOMAIN",
        "path": "/$HIDDEN_PATH"
      }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF

    sing-box check -c /etc/sing-box/config.json
    systemctl enable sing-box
    systemctl restart sing-box
    sleep 2

    if check_service sing-box "Sing-box" && check_port 8443; then
        log_info "Sing-box 运行正常"
    else
        error_handler "Sing-box 启动失败，请检查配置文件语法或端口冲突"
    fi

    # 本地测试 VLESS 隐藏路径（应返回 200 或 400？实际 sing-box 会返回 200 OK）
    test_http "http://127.0.0.1:8443/$HIDDEN_PATH" "200" "VLESS 隐藏路径"
}

# ======================== 最终健康报告 ========================
show_health_report() {
    log_step "最终服务健康报告"
    echo "----------------------------------------"
    check_service cloudflared "Cloudflare Tunnel"
    check_service caddy "Caddy"
    check_service sing-box "Sing-box"
    check_port 80 "HTTP"
    check_port 443 "HTTPS"
    check_port 8443 "VLESS 本地端口"
    echo "----------------------------------------"

    # 尝试通过 Cloudflare Tunnel 访问伪装网站（模拟外部请求）
    log_info "正在通过 Cloudflare Tunnel 检测公网访问..."
    TUNNEL_URL="https://${PROXY_DOMAIN}"
    if curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 "$TUNNEL_URL" | grep -q "200"; then
        log_info "伪装网站可从公网访问 ✔"
    else
        log_warn "伪装网站无法从公网访问，请检查："
        echo "  1) Cloudflare Tunnel 状态是否为 Active"
        echo "  2) DNS 解析是否生效 (dig ${PROXY_DOMAIN})"
        echo "  3) Cloudflare SSL/TLS 模式是否为 Full (strict)"
    fi
}

show_client_config() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}✨ 安装完成！✨${NC}"
    echo "=========================================="
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
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "ech": { "enabled": true }
      },
      "transport": {
        "type": "httpupgrade",
        "host": "$PROXY_DOMAIN",
        "path": "/$HIDDEN_PATH"
      },
      "multiplex": { "enabled": true, "protocol": "h2mux", "max_streams": 16 }
    }
  ]
}
EOF
    echo -e "${YELLOW}客户端配置文件: /root/client-config.json${NC}"
    ENCODED_PATH=$(echo -n "/$HIDDEN_PATH" | jq -sRr @uri)
    CLIENT_LINK="vless://${UUID}@${PROXY_DOMAIN}:443?encryption=none&security=tls&sni=${PROXY_DOMAIN}&fp=chrome&alpn=http/1.1&type=httpupgrade&host=${PROXY_DOMAIN}&path=${ENCODED_PATH}#CF-Tunnel-VLESS"
    echo -e "${YELLOW}VLESS 链接:${NC}"
    echo "$CLIENT_LINK"
    echo ""
    log_warn "最后检查清单（非常重要）："
    echo "  ✓ Cloudflare Dashboard → Zero Trust → Tunnels 确认状态为 Active"
    echo "  ✓ SSL/TLS 加密模式设为 Full (strict)"
    echo "  ✓ Edge Certificates 中启用 ECH (Encrypted Client Hello)"
    echo "  ✓ 客户端 DNS 使用 1.1.1.1 或 8.8.8.8 以支持 HTTPS RR"
}

# ======================== 主函数 ========================
main() {
    check_root
    check_system
    collect_input
    install_base_tools
    install_cloudflared
    install_caddy
    install_singbox
    configure_cloudflare_tunnel
    configure_website
    configure_caddy
    configure_singbox
    show_health_report
    show_client_config

    log_info "脚本执行完毕！如果看到任何 ✘ 标记，请根据提示进行手动干预。"
}

main "$@"
