#!/bin/bash

INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="ctyun"
CONFIG_DIR="$HOME/.ctyun"
REPO_URL="https://raw.githubusercontent.com/dxiaom/ctyun/main"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_python() {
    if command -v python3 &> /dev/null; then
        echo "python3"
    elif command -v python &> /dev/null; then
        echo "python"
    else
        echo ""
    fi
}

download_file() {
    local url="$1"
    local output="$2"
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$output"
    else
        log_error "需要 curl 或 wget 来下载文件"
        return 1
    fi
}

install_service() {
    PYTHON_CMD=$(check_python)
    if [ -z "$PYTHON_CMD" ]; then
        log_error "未找到 Python，请先安装 Python 3.8+"
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    log_info "检测到 Python 版本: $PYTHON_VERSION"
    
    mkdir -p "$CONFIG_DIR"
    
    log_info "正在下载文件..."
    
    download_file "$REPO_URL/ctyun_keepalive.py" "$CONFIG_DIR/ctyun_keepalive.py"
    if [ $? -ne 0 ]; then
        log_error "下载 ctyun_keepalive.py 失败"
        exit 1
    fi
    
    download_file "$REPO_URL/ctyun" "$INSTALL_DIR/ctyun"
    if [ $? -ne 0 ]; then
        log_error "下载 ctyun 失败"
        exit 1
    fi
    
    chmod +x "$INSTALL_DIR/ctyun"
    
    sed -i "s|__PYTHON_CMD__|$PYTHON_CMD|g" "$INSTALL_DIR/ctyun"
    sed -i "s|__CONFIG_DIR__|$CONFIG_DIR|g" "$INSTALL_DIR/ctyun"
    
    log_info "安装完成！"
    log_info "使用方法："
    echo "  ctyun config    - 配置账号密码"
    echo "  ctyun start     - 启动保活服务"
    echo "  ctyun stop      - 停止保活服务"
    echo "  ctyun restart   - 重启保活服务"
    echo "  ctyun status    - 查看服务状态"
    echo "  ctyun logs      - 查看日志"
    echo "  ctyun uninstall - 卸载服务"
}

uninstall_service() {
    log_info "正在卸载..."
    
    if [ -f "$INSTALL_DIR/ctyun" ]; then
        rm -f "$INSTALL_DIR/ctyun"
    fi
    
    if [ -d "$CONFIG_DIR" ]; then
        read -p "是否删除配置文件目录 $CONFIG_DIR？(y/n): " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            rm -rf "$CONFIG_DIR"
            log_info "配置文件已删除"
        fi
    fi
    
    log_info "卸载完成"
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "请使用 sudo 运行此脚本"
        exit 1
    fi
    
    case "${1:-install}" in
        install)
            install_service
            ;;
        uninstall)
            uninstall_service
            ;;
        *)
            log_error "未知命令: $1"
            echo "用法: $0 [install|uninstall]"
            exit 1
            ;;
    esac
}

main "$@"
