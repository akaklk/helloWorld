#!/bin/bash
# V2Ray VLESS + Reality 一键安装配置脚本
# 支持：Ubuntu/Debian/CentOS/Rocky/AlmaLinux
# 版本：v2.0
# 作者：VLESS-Reality-Auto

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
PLAIN="\033[0m"

info() {
    echo -e "${GREEN}[信息]${PLAIN} $1"
}

error() {
    echo -e "${RED}[错误]${PLAIN} $1"
    exit 1
}

warning() {
    echo -e "${YELLOW}[警告]${PLAIN} $1"
}

clear
echo "==============================================="
echo -e "${CYAN}   V2Ray VLESS + Reality 一键配置脚本   ${PLAIN}"
echo -e "${CYAN}        支持 XTLS-Reality 最新版       ${PLAIN}"
echo "==============================================="

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    error "请使用 root 用户运行此脚本！"
fi

# 检查系统
check_system() {
    if grep -qi "centos\|red hat\|redhat" /etc/os-release; then
        OS="centos"
    elif grep -qi "ubuntu\|debian" /etc/os-release; then
        OS="ubuntu"
    elif grep -qi "arch" /etc/os-release; then
        OS="arch"
    else
        error "不支持的系统！"
    fi
    info "检测到系统：${OS}"
}

# 安装依赖
install_deps() {
    info "安装系统依赖..."
    if [ "$OS" = "centos" ]; then
        yum install -y curl wget unzip tar jq openssl qrencode socat
    elif [ "$OS" = "ubuntu" ]; then
        apt update
        apt install -y curl wget unzip tar jq openssl qrencode socat
    elif [ "$OS" = "arch" ]; then
        pacman -Syu --noconfirm curl wget unzip tar jq openssl qrencode socat
    fi
}

# 安装 V2Ray
install_v2ray() {
    info "安装/更新 V2Ray..."
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    systemctl enable v2ray
    systemctl start v2ray
}

# 生成 Reality 密钥对
generate_keys() {
    info "生成 Reality 密钥对..."
    if ! command -v v2ray &> /dev/null; then
        error "V2Ray 未安装！"
    fi
    
    # 使用 v2ray 命令生成密钥对
    KEYS=$(v2ray x25519)
    PRIVATE_KEY=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEYS" | grep "Public key:" | awk '{print $3}')
    
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        error "生成密钥对失败！"
    fi
    
    # 生成短 ID
    SHORT_ID=$(openssl rand -hex 8)
    
    info "公钥: ${PUBLIC_KEY}"
    info "私钥: ${PRIVATE_KEY}"
    info "短ID: ${SHORT_ID}"
}

# 选择目标网站
select_target() {
    echo "请选择 Reality 的目标网站（用于伪装）："
    echo "1) www.apple.com (推荐)"
    echo "2) www.microsoft.com"
    echo "3) www.baidu.com"
    echo "4) 自定义"
    read -p "选择 [1-4] (默认1): " target_choice
    
    case $target_choice in
        1)
            TARGET="www.apple.com"
            ;;
        2)
            TARGET="www.microsoft.com"
            ;;
        3)
            TARGET="www.google.com"
            ;;
        4)
            read -p "请输入自定义目标网站（如：example.com）: " custom_target
            TARGET="${custom_target}"
            ;;
        *)
            TARGET="www.apple.com"
            ;;
    esac
    
    # 验证目标网站
    if ! timeout 5 curl -I "https://${TARGET}" >/dev/null 2>&1; then
        warning "无法访问 ${TARGET}，请确保目标网站可用！"
        read -p "是否继续？[y/N]: " continue_choice
        [[ "$continue_choice" != "y" && "$continue_choice" != "Y" ]] && exit 1
    fi
    
    info "目标网站: ${TARGET}"
}

# 配置服务器端口和UUID
configure_server() {
    read -p "请输入监听端口 [1-65535] (默认: 443): " PORT
    PORT=${PORT:-443}
    
    # 检查端口是否被占用
    if lsof -i:"$PORT" >/dev/null 2>&1; then
        warning "端口 $PORT 已被占用！"
        read -p "是否强制使用此端口？[y/N]: " force_port
        if [[ "$force_port" != "y" && "$force_port" != "Y" ]]; then
            read -p "请重新输入端口: " PORT
        fi
    fi
    
    # 生成 UUID
    UUID=$(cat /proc/sys/kernel/random/uuid)
    info "生成 UUID: ${UUID}"
    
    # 询问传输协议
    echo "请选择传输协议："
    echo "1) tcp (默认，推荐)"
    echo "2) grpc (抗干扰更强)"
    read -p "选择 [1-2] (默认1): " transport_choice
    
    case $transport_choice in
        1)
            NETWORK="tcp"
            ;;
        2)
            NETWORK="grpc"
            read -p "请输入 gRPC serviceName (默认: GunService): " SERVICE_NAME
            SERVICE_NAME=${SERVICE_NAME:-"GunService"}
            ;;
        *)
            NETWORK="tcp"
            ;;
    esac
}

# 生成服务器配置
generate_server_config() {
    info "生成服务器配置..."
    
    # 创建配置目录
    mkdir -p /usr/local/etc/v2ray/
    
    # 基本配置
    CONFIG_FILE="/usr/local/etc/v2ray/config.json"
    
    if [ "$NETWORK" = "grpc" ]; then
        cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "reality",
        "realitySettings": {
          "dest": "${TARGET}:443",
          "serverNames": ["${TARGET}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"],
          "spiderX": "/"
        },
        "grpcSettings": {
          "serviceName": "${SERVICE_NAME}"
        }
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
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": ["bittorrent"]
      }
    ]
  }
}
EOF
    else
        # TCP 配置
        cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "${TARGET}:443",
          "serverNames": ["${TARGET}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"],
          "spiderX": "/"
        }
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
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": ["bittorrent"]
      }
    ]
  }
}
EOF
    fi
    
    # 设置权限
    chmod 644 "$CONFIG_FILE"
}

# 重启 V2Ray
restart_v2ray() {
    info "重启 V2Ray 服务..."
    systemctl restart v2ray
    sleep 2
    
    # 检查服务状态
    if systemctl is-active --quiet v2ray; then
        info "V2Ray 服务运行正常！"
    else
        error "V2Ray 服务启动失败！请检查配置。"
    fi
    
    # 检查端口监听
    if ss -tuln | grep ":$PORT " >/dev/null 2>&1; then
        info "端口 ${PORT} 监听正常！"
    else
        warning "端口 ${PORT} 未监听，请检查防火墙设置！"
    fi
}

# 配置防火墙
configure_firewall() {
    info "配置防火墙..."
    
    if command -v ufw >/dev/null 2>&1; then
        ufw allow ${PORT}/tcp
        ufw reload
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=${PORT}/tcp
        firewall-cmd --reload
    elif command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4
        fi
    fi
    
    info "防火墙已放行端口 ${PORT}"
}

# 生成客户端配置
generate_client_config() {
    info "生成客户端配置..."
    
    # 获取服务器 IP
    SERVER_IP=$(curl -s -4 ip.sb || curl -s -4 icanhazip.com || curl -s -4 ifconfig.me)
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP="你的服务器IP"
    fi
    
    # 生成二维码内容
    if [ "$NETWORK" = "grpc" ]; then
        VLESS_URL="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${TARGET}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=grpc&serviceName=${SERVICE_NAME}#VLESS+Reality"
    else
        VLESS_URL="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${TARGET}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#VLESS+Reality"
    fi
    
    # 显示配置信息
    echo ""
    echo "==============================================="
    echo -e "${CYAN}         配置完成！客户端信息如下：        ${PLAIN}"
    echo "==============================================="
    echo ""
    echo -e "${GREEN}服务器地址:${PLAIN} ${SERVER_IP}"
    echo -e "${GREEN}端口:${PLAIN} ${PORT}"
    echo -e "${GREEN}UUID:${PLAIN} ${UUID}"
    echo -e "${GREEN}公钥:${PLAIN} ${PUBLIC_KEY}"
    echo -e "${GREEN}短ID:${PLAIN} ${SHORT_ID}"
    echo -e "${GREEN}目标网站:${PLAIN} ${TARGET}"
    echo -e "${GREEN}传输协议:${PLAIN} ${NETWORK}"
    if [ "$NETWORK" = "grpc" ]; then
        echo -e "${GREEN}gRPC serviceName:${PLAIN} ${SERVICE_NAME}"
    fi
    echo ""
    echo -e "${YELLOW}VLESS 链接:${PLAIN}"
    echo "${VLESS_URL}"
    echo ""
    
    # 生成二维码
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${CYAN}二维码：${PLAIN}"
        qrencode -t UTF8 "${VLESS_URL}"
    fi
    
    # 保存到文件
    CLIENT_INFO="/root/vless_reality_client.txt"
    cat > "$CLIENT_INFO" <<EOF
================ VLESS + Reality 配置 ================
服务器地址: ${SERVER_IP}
端口: ${PORT}
UUID: ${UUID}
公钥: ${PUBLIC_KEY}
短ID: ${SHORT_ID}
目标网站: ${TARGET}
传输协议: ${NETWORK}
EOF
    
    if [ "$NETWORK" = "grpc" ]; then
        echo "gRPC serviceName: ${SERVICE_NAME}" >> "$CLIENT_INFO"
    fi
    
    echo "VLESS 链接:" >> "$CLIENT_INFO"
    echo "${VLESS_URL}" >> "$CLIENT_INFO"
    
    info "客户端配置已保存至: ${CLIENT_INFO}"
    
    # 生成 NekoRay 配置
    NEKO_CONFIG="/root/vless_reality_nekoray.json"
    cat > "$NEKO_CONFIG" <<EOF
{
  "v": "2",
  "ps": "VLESS+Reality",
  "add": "${SERVER_IP}",
  "port": "${PORT}",
  "id": "${UUID}",
  "aid": "0",
  "scy": "none",
  "net": "${NETWORK}",
  "type": "none",
  "host": "",
  "path": "${SERVICE_NAME}",
  "tls": "reality",
  "sni": "${TARGET}",
  "alpn": "",
  "fp": "chrome",
  "pbk": "${PUBLIC_KEY}",
  "sid": "${SHORT_ID}"
}
EOF
    
    info "NekoRay 配置已保存至: ${NEKO_CONFIG}"
}

# 显示帮助信息
show_help() {
    echo ""
    echo "==============================================="
    echo -e "${CYAN}          使用说明和注意事项            ${PLAIN}"
    echo "==============================================="
    echo ""
    echo "1. 客户端推荐使用："
    echo "   - v2rayNG (Android)"
    echo "   - NekoRay (Windows)"
    echo "   - sing-box (全平台)"
    echo ""
    echo "2. 如需更新配置，请重新运行此脚本"
    echo ""
    echo "3. 管理命令："
    echo "   systemctl start v2ray     # 启动"
    echo "   systemctl stop v2ray      # 停止"
    echo "   systemctl restart v2ray   # 重启"
    echo "   systemctl status v2ray    # 状态"
    echo ""
    echo "4. 查看日志："
    echo "   tail -f /var/log/v2ray/error.log"
    echo "   tail -f /var/log/v2ray/access.log"
    echo ""
}

# 卸载功能（可选）
uninstall() {
    warning "这将卸载 V2Ray 并删除所有配置！"
    read -p "确定要卸载吗？[y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "已取消卸载"
        exit 0
    fi
    
    systemctl stop v2ray
    systemctl disable v2ray
    rm -rf /usr/bin/v2ray /etc/v2ray /var/log/v2ray /usr/local/share/v2ray /usr/local/etc/v2ray
    rm -f /etc/systemd/system/v2ray.service /etc/systemd/system/v2ray@.service
    
    info "V2Ray 已卸载完成！"
    exit 0
}

# 主函数
main() {
    # 检查参数
    if [[ $# -gt 0 ]]; then
        case $1 in
            "uninstall"|"remove")
                uninstall
                ;;
            "help"|"-h"|"--help")
                echo "用法: $0 [option]"
                echo "  uninstall - 卸载 V2Ray"
                echo "  help      - 显示帮助"
                exit 0
                ;;
            *)
                error "未知参数: $1"
                ;;
        esac
    fi
    
    # 执行安装流程
    check_system
    install_deps
    install_v2ray
    select_target
    configure_server
    generate_keys
    generate_server_config
    configure_firewall
    restart_v2ray
    generate_client_config
    show_help
    
    echo ""
    info "安装配置完成！请保存好上面的客户端信息。"
    echo ""
}

# 执行主函数
main "$@"