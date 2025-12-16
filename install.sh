#!/bin/bash
# ===============================================
# V2Ray VLESS + Reality 一键安装配置脚本（小白友好版）
# 支持：Ubuntu/Debian/CentOS/Rocky/AlmaLinux
# 版本：v2.0
# 作者：V2Ray助手
# ===============================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # 无颜色

# 配置文件路径
CONFIG_DIR="/etc/v2ray-config"
CONFIG_FILE="$CONFIG_DIR/config.json"
CLIENT_INFO="$CONFIG_DIR/client-info.txt"
BACKUP_DIR="$CONFIG_DIR/backups"

# 默认配置
DEFAULT_PORT=443
DEFAULT_TARGET="www.apple.com"
DEFAULT_PROTOCOL="tcp"

# 显示菜单
show_menu() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║      V2Ray VLESS + Reality 管理面板      ║"
    echo "╠═══════════════════════════════════════════╣"
    echo "║  1. 一键安装并配置 Reality (推荐)        ║"
    echo "║  2. 修改服务器配置                       ║"
    echo "║  3. 生成新的客户端配置                   ║"
    echo "║  4. 显示当前配置信息                     ║"
    echo "║  5. 重启 V2Ray 服务                      ║"
    echo "║  6. 查看运行状态和日志                   ║"
    echo "║  7. 备份当前配置                         ║"
    echo "║  8. 恢复备份配置                         ║"
    echo "║  9. 卸载 V2Ray                          ║"
    echo "║  0. 退出                                ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# 显示信息
show_info() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# 显示警告
show_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# 显示错误
show_error() {
    echo -e "${RED}[✗] $1${NC}"
}

# 等待用户按键
press_any_key() {
    echo -e "${CYAN}"
    read -n 1 -s -r -p "按任意键继续..."
    echo -e "${NC}"
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        show_error "请使用 root 用户运行此脚本！"
        echo "请使用: sudo bash $0"
        exit 1
    fi
}

# 检查系统
check_system() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        show_error "无法检测操作系统！"
        exit 1
    fi
    
    case $OS in
        ubuntu|debian)
            PM="apt"
            ;;
        centos|rhel|fedora|rocky|alma)
            PM="yum"
            ;;
        *)
            show_error "不支持的操作系统: $OS"
            exit 1
            ;;
    esac
    
    show_info "检测到系统: $OS"
}

# 安装依赖
install_dependencies() {
    show_info "安装必要依赖..."
    
    if [ "$PM" = "apt" ]; then
        apt update
        apt install -y curl wget unzip tar jq openssl qrencode socat net-tools
    elif [ "$PM" = "yum" ]; then
        yum install -y curl wget unzip tar jq openssl qrencode socat net-tools
    fi
    
    # 安装 wireguard-tools 用于生成密钥
    if ! command -v wg &> /dev/null; then
        show_info "安装 wireguard-tools 用于生成密钥..."
        if [ "$PM" = "apt" ]; then
            apt install -y wireguard-tools
        elif [ "$PM" = "yum" ]; then
            yum install -y wireguard-tools
        fi
    fi
}

# 安装 V2Ray
install_v2ray() {
    if command -v v2ray &> /dev/null; then
        show_info "V2Ray 已安装，跳过安装步骤"
        return
    fi
    
    show_info "安装 V2Ray..."
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    if ! command -v v2ray &> /dev/null; then
        show_error "V2Ray 安装失败！"
        exit 1
    fi
    
    systemctl enable v2ray
    systemctl start v2ray
    show_info "V2Ray 安装完成"
}

# 生成密钥
generate_keys() {
    show_info "生成密钥..."
    
    # 尝试使用 wg 命令生成密钥
    if command -v wg &> /dev/null; then
        WG_PRIVKEY=$(wg genkey)
        WG_PUBKEY=$(echo "$WG_PRIVKEY" | wg pubkey)
        
        # 转换为 base64（去掉等号）
        PRIVATE_KEY=$(echo "$WG_PRIVKEY" | base64 | tr -d '\n' | tr -d '=')
        PUBLIC_KEY=$(echo "$WG_PUBKEY" | base64 | tr -d '\n' | tr -d '=')
        
        show_info "使用 wireguard-tools 生成密钥"
    else
        # 备用方法：使用 openssl
        show_warning "wg 命令不可用，使用 openssl 生成密钥"
        
        # 生成 x25519 密钥对
        openssl genpkey -algorithm x25519 -out /tmp/private.pem
        PRIVATE_KEY=$(openssl pkey -in /tmp/private.pem -text -noout | grep -A 2 'X25519 Private-Key' | tail -1 | tr -d ' ' | base64 | tr -d '\n')
        PUBLIC_KEY=$(openssl pkey -in /tmp/private.pem -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
        
        rm -f /tmp/private.pem
    fi
    
    # 生成短 ID
    SHORT_ID=$(openssl rand -hex 8)
    
    # 生成 UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # 保存密钥到文件
    echo "UUID=$UUID" > "$CONFIG_DIR/keys.txt"
    echo "PRIVATE_KEY=$PRIVATE_KEY" >> "$CONFIG_DIR/keys.txt"
    echo "PUBLIC_KEY=$PUBLIC_KEY" >> "$CONFIG_DIR/keys.txt"
    echo "SHORT_ID=$SHORT_ID" >> "$CONFIG_DIR/keys.txt"
    
    show_info "密钥生成完成"
    echo -e "${CYAN}"
    echo "UUID: $UUID"
    echo "公钥: $PUBLIC_KEY"
    echo "短ID: $SHORT_ID"
    echo -e "${NC}"
}

# 交互式配置
interactive_config() {
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════"
    echo "            配置 V2Ray Reality 服务"
    echo "═══════════════════════════════════════════════"
    echo -e "${NC}"
    
    # 端口配置
    read -p "请输入监听端口 [默认: $DEFAULT_PORT]: " PORT
    PORT=${PORT:-$DEFAULT_PORT}
    
    # 检查端口是否被占用
    if ss -tuln | grep -q ":$PORT "; then
        show_warning "端口 $PORT 已被占用！"
        read -p "是否强制使用此端口？[y/N]: " force_port
        if [[ ! "$force_port" =~ ^[Yy]$ ]]; then
            interactive_config
            return
        fi
    fi
    
    # 目标网站选择
    echo ""
    echo "请选择目标网站（用于伪装流量）："
    echo "1) www.apple.com (推荐，稳定性好)"
    echo "2) www.microsoft.com"
    echo "3) www.google.com"
    echo "4) www.github.com"
    echo "5) 自定义"
    echo ""
    read -p "请选择 [1-5, 默认1]: " target_choice
    
    case $target_choice in
        1) TARGET="www.apple.com" ;;
        2) TARGET="www.microsoft.com" ;;
        3) TARGET="www.google.com" ;;
        4) TARGET="www.github.com" ;;
        5) 
            read -p "请输入自定义域名: " custom_target
            TARGET=${custom_target:-"www.apple.com"}
            ;;
        *) TARGET="www.apple.com" ;;
    esac
    
    # 传输协议选择
    echo ""
    echo "请选择传输协议："
    echo "1) TCP (默认，兼容性好)"
    echo "2) gRPC (抗干扰强，推荐)"
    echo "3) WebSocket (适合CDN)"
    echo ""
    read -p "请选择 [1-3, 默认1]: " protocol_choice
    
    case $protocol_choice in
        1) 
            PROTOCOL="tcp"
            EXTRA_CONFIG=""
            ;;
        2)
            PROTOCOL="grpc"
            read -p "请输入 gRPC 服务名称 [默认: GunService]: " SERVICE_NAME
            SERVICE_NAME=${SERVICE_NAME:-"GunService"}
            EXTRA_CONFIG=",
        \"grpcSettings\": {
          \"serviceName\": \"$SERVICE_NAME\",
          \"multiMode\": true
        }"
            ;;
        3)
            PROTOCOL="ws"
            read -p "请输入 WebSocket 路径 [默认: /ray]: " WS_PATH
            WS_PATH=${WS_PATH:-"/ray"}
            EXTRA_CONFIG=",
        \"wsSettings\": {
          \"path\": \"$WS_PATH\",
          \"headers\": {
            \"Host\": \"$TARGET\"
          }
        }"
            ;;
        *)
            PROTOCOL="tcp"
            EXTRA_CONFIG=""
            ;;
    esac
    
    # 保存配置
    echo "PORT=$PORT" > "$CONFIG_DIR/settings.txt"
    echo "TARGET=$TARGET" >> "$CONFIG_DIR/settings.txt"
    echo "PROTOCOL=$PROTOCOL" >> "$CONFIG_DIR/settings.txt"
    
    if [ "$PROTOCOL" = "grpc" ]; then
        echo "SERVICE_NAME=$SERVICE_NAME" >> "$CONFIG_DIR/settings.txt"
    elif [ "$PROTOCOL" = "ws" ]; then
        echo "WS_PATH=$WS_PATH" >> "$CONFIG_DIR/settings.txt"
    fi
    
    show_info "配置已保存"
}

# 生成配置文件
generate_config() {
    # 加载配置
    if [ -f "$CONFIG_DIR/settings.txt" ]; then
        source "$CONFIG_DIR/settings.txt"
    else
        show_error "找不到配置文件！请先运行配置向导。"
        return 1
    fi
    
    if [ -f "$CONFIG_DIR/keys.txt" ]; then
        source "$CONFIG_DIR/keys.txt"
    else
        show_error "找不到密钥文件！请先生成密钥。"
        return 1
    fi
    
    show_info "生成 V2Ray 配置文件..."
    
    # 创建配置文件
    cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "$PROTOCOL",
        "security": "reality",
        "realitySettings": {
          "dest": "$TARGET:443",
          "serverNames": ["$TARGET"],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": ["$SHORT_ID"],
          "spiderX": "/"
        }$EXTRA_CONFIG
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ]
}
EOF
    
    # 复制到 V2Ray 配置目录
    cp "$CONFIG_FILE" /usr/local/etc/v2ray/config.json
    
    show_info "配置文件生成完成"
}

# 配置防火墙
configure_firewall() {
    if [ -f "$CONFIG_DIR/settings.txt" ]; then
        source "$CONFIG_DIR/settings.txt"
    else
        return
    fi
    
    show_info "配置防火墙..."
    
    # 检查 UFW
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $PORT/tcp 2>/dev/null
        ufw reload 2>/dev/null
        show_info "UFW 防火墙已配置"
    fi
    
    # 检查 firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$PORT/tcp 2>/dev/null
        firewall-cmd --reload 2>/dev/null
        show_info "firewalld 防火墙已配置"
    fi
    
    # 配置 iptables
    iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null
    
    show_info "防火墙配置完成"
}

# 重启服务
restart_service() {
    show_info "重启 V2Ray 服务..."
    
    systemctl daemon-reload
    systemctl restart v2ray
    
    # 检查服务状态
    sleep 2
    if systemctl is-active --quiet v2ray; then
        show_info "✅ V2Ray 服务运行正常"
    else
        show_error "❌ V2Ray 服务启动失败"
        echo "请查看日志: journalctl -u v2ray -n 50 --no-pager"
    fi
}

# 显示客户端信息
show_client_info() {
    if [ ! -f "$CONFIG_DIR/keys.txt" ] || [ ! -f "$CONFIG_DIR/settings.txt" ]; then
        show_error "配置信息不完整，请先完成安装配置"
        return
    fi
    
    source "$CONFIG_DIR/keys.txt"
    source "$CONFIG_DIR/settings.txt"
    
    # 获取服务器 IP
    SERVER_IP=$(curl -s -4 ip.sb || curl -s -4 icanhazip.com || curl -s -4 ifconfig.me || echo "您的服务器IP")
    
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║       客户端连接信息 (请保存好)          ║"
    echo "╠═══════════════════════════════════════════╣"
    echo -e "${NC}"
    
    echo "服务器地址: $SERVER_IP"
    echo "端口: $PORT"
    echo "UUID: $UUID"
    echo "公钥: $PUBLIC_KEY"
    echo "短ID: $SHORT_ID"
    echo "目标网站: $TARGET"
    echo "传输协议: $PROTOCOL"
    
    if [ "$PROTOCOL" = "grpc" ]; then
        echo "gRPC 服务名: $SERVICE_NAME"
    elif [ "$PROTOCOL" = "ws" ]; then
        echo "WebSocket 路径: $WS_PATH"
    fi
    
    echo ""
    
    # 生成客户端链接
    if [ "$PROTOCOL" = "grpc" ]; then
        VLESS_URL="vless://$UUID@$SERVER_IP:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$TARGET&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=grpc&serviceName=$SERVICE_NAME#V2Ray-Reality"
    elif [ "$PROTOCOL" = "ws" ]; then
        VLESS_URL="vless://$UUID@$SERVER_IP:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$TARGET&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=ws&path=$WS_PATH#V2Ray-Reality"
    else
        VLESS_URL="vless://$UUID@$SERVER_IP:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$TARGET&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp#V2Ray-Reality"
    fi
    
    echo "VLESS 链接:"
    echo "$VLESS_URL"
    echo ""
    
    # 生成二维码
    if command -v qrencode >/dev/null 2>&1; then
        echo "二维码 (使用客户端扫码导入):"
        qrencode -t ANSIUTF8 "$VLESS_URL"
    fi
    
    echo ""
    echo -e "${YELLOW}客户端推荐：${NC}"
    echo "Windows: v2rayN, NekoRay"
    echo "Android: v2rayNG"
    echo "iOS: Shadowrocket, Stash"
    echo "macOS: V2RayX, ClashX"
    
    # 保存到文件
    cat > "$CLIENT_INFO" <<EOF
=== V2Ray Reality 客户端配置 ===
生成时间: $(date)

服务器地址: $SERVER_IP
端口: $PORT
UUID: $UUID
公钥: $PUBLIC_KEY
短ID: $SHORT_ID
目标网站: $TARGET
传输协议: $PROTOCOL
EOF
    
    if [ "$PROTOCOL" = "grpc" ]; then
        echo "gRPC 服务名: $SERVICE_NAME" >> "$CLIENT_INFO"
    elif [ "$PROTOCOL" = "ws" ]; then
        echo "WebSocket 路径: $WS_PATH" >> "$CLIENT_INFO"
    fi
    
    echo "" >> "$CLIENT_INFO"
    echo "VLESS 链接:" >> "$CLIENT_INFO"
    echo "$VLESS_URL" >> "$CLIENT_INFO"
    
    echo ""
    show_info "配置已保存到: $CLIENT_INFO"
    echo "您可以使用 cat $CLIENT_INFO 查看"
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
}

# 显示当前配置
show_current_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        show_error "配置文件不存在，请先安装配置"
        return
    fi
    
    show_info "当前 V2Ray 配置:"
    echo ""
    echo "配置文件位置: $CONFIG_FILE"
    echo ""
    
    # 显示主要配置信息
    echo -e "${CYAN}[监听设置]${NC}"
    PORT=$(jq -r '.inbounds[0].port' "$CONFIG_FILE" 2>/dev/null || echo "无法读取")
    echo "端口: $PORT"
    
    echo ""
    echo -e "${CYAN}[协议设置]${NC}"
    UUID=$(jq -r '.inbounds[0].settings.clients[0].id' "$CONFIG_FILE" 2>/dev/null || echo "无法读取")
    echo "UUID: $UUID"
    
    echo ""
    echo -e "${CYAN}[Reality 设置]${NC}"
    TARGET=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$CONFIG_FILE" 2>/dev/null | cut -d: -f1 || echo "无法读取")
    echo "目标网站: $TARGET"
    
    echo ""
    echo -e "${CYAN}[服务状态]${NC}"
    systemctl status v2ray --no-pager -l
}

# 备份配置
backup_config() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
    fi
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/config_backup_$TIMESTAMP.tar.gz"
    
    tar -czf "$BACKUP_FILE" -C "$CONFIG_DIR" . 2>/dev/null
    
    if [ $? -eq 0 ]; then
        show_info "配置已备份到: $BACKUP_FILE"
    else
        show_error "备份失败"
    fi
}

# 恢复配置
restore_config() {
    if [ ! -d "$BACKUP_DIR" ]; then
        show_error "备份目录不存在"
        return
    fi
    
    # 列出备份文件
    BACKUP_FILES=("$BACKUP_DIR"/*.tar.gz)
    
    if [ ${#BACKUP_FILES[@]} -eq 0 ]; then
        show_error "没有找到备份文件"
        return
    fi
    
    echo "可用的备份文件:"
    echo ""
    
    for i in "${!BACKUP_FILES[@]}"; do
        echo "$((i+1)). ${BACKUP_FILES[$i]##*/}"
    done
    
    echo ""
    read -p "请选择要恢复的备份 [1-${#BACKUP_FILES[@]}]: " backup_choice
    
    if [[ ! "$backup_choice" =~ ^[0-9]+$ ]] || [ "$backup_choice" -lt 1 ] || [ "$backup_choice" -gt ${#BACKUP_FILES[@]} ]; then
        show_error "选择无效"
        return
    fi
    
    SELECTED_BACKUP="${BACKUP_FILES[$((backup_choice-1))]}"
    
    show_warning "即将恢复备份，当前配置将被覆盖！"
    read -p "确定要恢复吗？[y/N]: " confirm_restore
    
    if [[ "$confirm_restore" =~ ^[Yy]$ ]]; then
        # 备份当前配置
        tar -czf "$BACKUP_DIR/config_before_restore_$(date +%Y%m%d_%H%M%S).tar.gz" -C "$CONFIG_DIR" . 2>/dev/null
        
        # 恢复备份
        tar -xzf "$SELECTED_BACKUP" -C "$CONFIG_DIR"
        
        if [ $? -eq 0 ]; then
            show_info "配置恢复成功"
            
            # 询问是否重启服务
            read -p "是否重启 V2Ray 服务使配置生效？[Y/n]: " restart_confirm
            restart_confirm=${restart_confirm:-Y}
            
            if [[ "$restart_confirm" =~ ^[Yy]$ ]]; then
                cp "$CONFIG_FILE" /usr/local/etc/v2ray/config.json
                restart_service
            fi
        else
            show_error "配置恢复失败"
        fi
    else
        show_info "已取消恢复"
    fi
}

# 卸载 V2Ray
uninstall_v2ray() {
    show_warning "⚠️  这将卸载 V2Ray 并删除所有配置文件！"
    echo ""
    echo "将删除以下内容："
    echo "1. V2Ray 程序文件"
    echo "2. 配置文件 ($CONFIG_DIR)"
    echo "3. 系统服务"
    echo ""
    read -p "确定要卸载吗？[y/N]: " confirm_uninstall
    
    if [[ "$confirm_uninstall" =~ ^[Yy]$ ]]; then
        # 停止服务
        systemctl stop v2ray 2>/dev/null
        systemctl disable v2ray 2>/dev/null
        
        # 卸载 V2Ray
        rm -rf /usr/local/bin/v2ray /usr/local/bin/v2ctl
        rm -rf /usr/local/lib/v2ray/
        rm -rf /usr/local/share/v2ray/
        rm -f /etc/systemd/system/v2ray.service
        rm -f /etc/systemd/system/v2ray@.service
        
        # 删除配置文件
        rm -rf "$CONFIG_DIR"
        
        show_info "V2Ray 已卸载完成"
    else
        show_info "卸载已取消"
    fi
}

# 一键安装
one_click_install() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║        V2Ray Reality 一键安装向导        ║"
    echo "╠═══════════════════════════════════════════╣"
    echo -e "${NC}"
    
    check_root
    check_system
    
    echo ""
    echo "开始安装，请稍候..."
    echo ""
    
    # 创建配置目录
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # 安装依赖
    install_dependencies
    
    # 安装 V2Ray
    install_v2ray
    
    # 生成密钥
    generate_keys
    
    # 交互式配置
    interactive_config
    
    # 生成配置文件
    generate_config
    
    # 配置防火墙
    configure_firewall
    
    # 重启服务
    restart_service
    
    # 显示客户端信息
    show_client_info
    
    echo ""
    show_info "✅ 安装完成！"
    echo ""
    echo "管理命令："
    echo "1. 重启服务: systemctl restart v2ray"
    echo "2. 查看状态: systemctl status v2ray"
    echo "3. 查看日志: journalctl -u v2ray -f"
    echo ""
    echo "配置文件位置: $CONFIG_FILE"
    echo "客户端信息: $CLIENT_INFO"
    echo ""
    echo "下次运行此脚本可修改配置：bash $0"
    
    press_any_key
}

# 初始化检查
initialize() {
    # 创建配置目录
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # 检查是否已安装
    if [ ! -f "$CONFIG_DIR/settings.txt" ]; then
        echo "欢迎使用 V2Ray Reality 一键脚本！"
        echo ""
        read -p "检测到新安装，是否开始一键安装？[Y/n]: " start_install
        start_install=${start_install:-Y}
        
        if [[ "$start_install" =~ ^[Yy]$ ]]; then
            one_click_install
        else
            show_menu
        fi
    else
        show_menu
    fi
}

# 主函数
main() {
    # 检查参数
    if [ $# -gt 0 ]; then
        case $1 in
            "install")
                one_click_install
                exit 0
                ;;
            "status")
                systemctl status v2ray
                exit 0
                ;;
            "restart")
                restart_service
                exit 0
                ;;
            "config")
                show_client_info
                exit 0
                ;;
            "help"|"-h"|"--help")
                echo "使用方法: $0 [选项]"
                echo "  无参数    - 显示管理菜单"
                echo "  install   - 一键安装"
                echo "  status    - 查看服务状态"
                echo "  restart   - 重启服务"
                echo "  config    - 显示客户端配置"
                echo "  help      - 显示帮助"
                exit 0
                ;;
        esac
    fi
    
    # 显示菜单
    while true; do
        show_menu
        
        read -p "请选择操作 [0-9]: " choice
        
        case $choice in
            1)
                one_click_install
                ;;
            2)
                interactive_config
                generate_config
                cp "$CONFIG_FILE" /usr/local/etc/v2ray/config.json
                restart_service
                show_info "配置已更新并重启服务"
                press_any_key
                ;;
            3)
                generate_keys
                show_client_info
                press_any_key
                ;;
            4)
                show_current_config
                press_any_key
                ;;
            5)
                restart_service
                press_any_key
                ;;
            6)
                clear
                echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
                echo "V2Ray 服务状态:"
                systemctl status v2ray --no-pager -l
                echo ""
                echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
                echo "实时日志 (Ctrl+C 退出):"
                echo ""
                journalctl -u v2ray -f --no-pager -n 20
                ;;
            7)
                backup_config
                press_any_key
                ;;
            8)
                restore_config
                press_any_key
                ;;
            9)
                uninstall_v2ray
                press_any_key
                ;;
            0)
                echo "再见！"
                exit 0
                ;;
            *)
                show_error "无效选择，请重新输入"
                sleep 2
                ;;
        esac
    done
}

# 启动脚本
clear
echo -e "${CYAN}"
cat << "EOF"
__      _______ _____  _____   _____ 
\ \    / /_   _|  __ \|  __ \ / ____|
 \ \  / /  | | | |__) | |__) | |     
  \ \/ /   | | |  _  /|  _  /| |     
   \  /   _| |_| | \ \| | \ \| |____ 
    \/   |_____|_|  \_\_|  \_\\_____|
                                     
    V2Ray VLESS + Reality 一键脚本
        小白友好，配置简单
EOF
echo -e "${NC}"

# 初始化并运行
initialize
main "$@"
