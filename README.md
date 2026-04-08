# CtYun 云桌面保活脚本

天翼云桌面连接保活工具

## 安装

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/dxiaom/ctyun/main/install.sh | sudo bash
```

或

```bash
wget -qO- https://raw.githubusercontent.com/dxiaom/ctyun/main/install.sh | sudo bash
```

安装完成后，`ctyun` 命令将被安装到 `/usr/local/bin/`，可以在任意目录使用。

### 手动安装

```bash
git clone https://github.com/dxiaom/ctyun.git
cd ctyun
sudo bash install.sh
```

## 使用方法

### 配置账号

首次使用需要配置天翼云账号：

```bash
ctyun config
```

按提示输入账号和密码，支持添加多个账户。

### 启动服务

```bash
ctyun start
```

### 停止服务

```bash
ctyun stop
```

### 重启服务

```bash
ctyun restart
```

### 查看状态

```bash
ctyun status
```

### 查看日志

```bash
# 查看最近日志
ctyun logs

# 实时查看日志
ctyun logs -f
```

### 卸载

```bash
ctyun uninstall
```

## 手动运行

```bash
python ctyun_keepalive.py
```

## 项目特点

- 代码使用标准库实现，无需安装额外依赖
- 支持 Python 3.8+
- 配置文件加密存储，保护账号安全
- 后台运行，支持服务管理

## 文件说明

| 文件 | 说明 |
|------|------|
| `install.sh` | 安装脚本 |
| `ctyun` | 管理命令脚本 |
| `ctyun_keepalive.py` | Python 保活脚本 |

## 配置文件

配置文件存储在 `~/.ctyun/` 目录下：

- `config.json` - 加密的账号配置
- `ctyun.pid` - 服务进程 ID
- `ctyun.log` - 运行日志

## 注意事项

1. 需要安装 Python 3.8+
2. 首次使用需要绑定设备，会发送短信验证码
3. 如果云电脑未开机，脚本会尝试开机，需要等待约 2 分钟后重新运行
