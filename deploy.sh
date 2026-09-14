#!/bin/bash
# hy2-multiroute 部署脚本
# 在服务器上运行：把面板生成的 config.json 放到 /etc/hy2/ 后执行
set -e

SINGBOX_VER="1.11.15"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

echo "=== 1. 安装 sing-box ==="
if ! command -v sing-box >/dev/null; then
  curl -Lo /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-linux-${ARCH}.tar.gz"
  tar -xzf /tmp/sing-box.tar.gz -C /tmp
  cp /tmp/sing-box-*/sing-box /usr/local/bin/
  chmod +x /usr/local/bin/sing-box
fi
sing-box version | head -1

echo "=== 2. 准备证书（自签） ==="
mkdir -p /etc/hy2
if [ ! -f /etc/hy2/cert.pem ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out /etc/hy2/key.pem
  openssl req -new -x509 -key /etc/hy2/key.pem -out /etc/hy2/cert.pem -days 3650 -subj "/CN=hy2.local"
fi

echo "=== 3. 写入配置 ==="
if [ -f "$1" ]; then cp "$1" /etc/hy2/config.json; fi
[ -f /etc/hy2/config.json ] || { echo "缺少 /etc/hy2/config.json（先从面板生成并上传）"; exit 1; }
sing-box check -c /etc/hy2/config.json && echo "配置校验通过"

echo "=== 4. systemd 服务 ==="
cat > /etc/systemd/system/hy2.service <<EOF
[Unit]
Description=hy2 multiroute (sing-box)
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/hy2/config.json
Restart=always
RestartSec=5
LimitNOFILE=65535
MemoryMax=96M

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now hy2
sleep 1
systemctl is-active hy2 && echo "=== 部署完成，服务已启动 ==="
