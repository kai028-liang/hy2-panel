#!/usr/bin/env python3
"""hy2-multiroute 面板后端

功能：
- 账号密码登录（session）
- 管理规则：入站协议+端口 -> 上游代理出口（不同端口流量从不同代理 IP 出去）
- 入站协议：hy2 / ss(Shadowsocks) / trojan / vless+REALITY
- 自动生成自签证书、REALITY 密钥对
- 生成 sing-box 配置（多端口入站 + 按入站 tag 分流出站）
"""
import os
import json
import base64
import uuid
import shutil
import secrets
import subprocess
import threading
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
CERT_DIR = os.path.join(DATA_DIR, "certs")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
RULES_FILE = os.path.join(DATA_DIR, "rules.json")
REALITY_FILE = os.path.join(DATA_DIR, "reality.json")
GEN_DIR = os.path.join(DATA_DIR, "generated")

for d in (DATA_DIR, CERT_DIR, GEN_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(__name__, static_folder="static")
app.secret_key = secrets.token_hex(32) if not os.path.exists(os.path.join(DATA_DIR, "secret_key")) else open(os.path.join(DATA_DIR, "secret_key")).read().strip()


def _init_secret():
    f = os.path.join(DATA_DIR, "secret_key")
    if not os.path.exists(f):
        with open(f, "w") as fh:
            fh.write(secrets.token_hex(32))
    app.secret_key = open(f).read().strip()


_init_secret()


# ---------- 用户 ----------
def load_users():
    if not os.path.exists(USERS_FILE):
        # 默认账号 admin / admin123，首次登录后请修改
        from werkzeug.security import generate_password_hash
        with open(USERS_FILE, "w") as f:
            json.dump({"admin": {"password": generate_password_hash("admin123")}}, f)
    with open(USERS_FILE) as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "未登录"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.post("/api/login")
def login():
    data = request.get_json()
    users = load_users()
    from werkzeug.security import check_password_hash
    u = users.get(data.get("username", ""))
    if u and check_password_hash(u["password"], data.get("password", "")):
        session["user"] = data["username"]
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"error": "用户名或密码错误"}), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/change_password")
@login_required
def change_password():
    data = request.get_json()
    old, new = data.get("old", ""), data.get("new", "")
    if len(new) < 6:
        return jsonify({"error": "新密码至少 6 位"}), 400
    users = load_users()
    from werkzeug.security import check_password_hash, generate_password_hash
    if not check_password_hash(users[session["user"]]["password"], old):
        return jsonify({"error": "旧密码错误"}), 400
    users[session["user"]]["password"] = generate_password_hash(new)
    save_users(users)
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    if "user" in session:
        return jsonify({"user": session["user"]})
    return jsonify({"user": None})


# ---------- 证书 ----------
def ensure_cert(cert_dir=CERT_DIR, cn="hy2.local"):
    """用 openssl 生成自签证书（有效期 10 年）。兼容 Git-Bash 的 MSYS 路径转换问题。"""
    cert = os.path.join(cert_dir, "cert.pem")
    key = os.path.join(cert_dir, "key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    openssl = shutil.which("openssl") or "openssl"
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    subprocess.run([openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                    "-out", key], check=True, capture_output=True, env=env)
    subprocess.run([openssl, "req", "-new", "-x509", "-key", key, "-out", cert,
                    "-days", "3650", "-subj", f"//CN={cn}"],
                   check=True, capture_output=True, env=env)
    return cert, key


# ---------- REALITY ----------
# 伪装目标站预设（可随时切换）：要求目标站支持 TLS1.3 + H2，且不在墙黑名单
REALITY_PRESETS = [
    {"id": "microsoft", "name": "Microsoft", "server": "www.microsoft.com", "server_port": 443},
    {"id": "apple", "name": "Apple", "server": "www.apple.com", "server_port": 443},
    {"id": "yahoo", "name": "Yahoo", "server": "www.yahoo.com", "server_port": 443},
    {"id": "bing", "name": "Bing", "server": "www.bing.com", "server_port": 443},
    {"id": "samsung", "name": "Samsung", "server": "www.samsung.com", "server_port": 443},
]


def ensure_reality():
    """REALITY 密钥对（X25519），只生成一次存盘；优先用 cryptography 库，退回 sing-box CLI"""
    if os.path.exists(REALITY_FILE):
        with open(REALITY_FILE) as f:
            return json.load(f)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
        u = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
        data = {"private_key": u(b), "public_key": u(pub), "short_id": secrets.token_hex(8)}
    except (ImportError, FileNotFoundError, subprocess.CalledProcessError, json.JSONDecodeError):
        p = subprocess.run(["sing-box", "generate", "reality-keypair"],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError("无法生成 REALITY 密钥：缺 cryptography 库且 sing-box 不可用")
        d = json.loads(p.stdout)
        data = {"private_key": d["PrivateKey"], "public_key": d["PublicKey"],
                "short_id": secrets.token_hex(8)}
    with open(REALITY_FILE, "w") as f:
        json.dump(data, f)
    return data


def get_reality_preset(pid):
    for p in REALITY_PRESETS:
        if p["id"] == pid:
            return p
    return REALITY_PRESETS[0]


# ---------- 规则 ----------
def load_rules():
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w") as f:
            json.dump({"rules": []}, f)
    with open(RULES_FILE) as f:
        return json.load(f)


def save_rules(data):
    with open(RULES_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


VALID_OUT_TYPES = {"direct", "socks", "http", "hy2"}
VALID_PROTOS = {"hy2", "ss", "trojan", "vless"}
SS_METHODS = {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-256-gcm"}


def validate_rule(r):
    proto = r.get("proto", "hy2")
    if proto not in VALID_PROTOS:
        return "协议必须是 hy2/ss/trojan/vless"
    try:
        port = int(r["listen_port"])
        if not (1 <= port <= 65535):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        return "入站端口必须是 1-65535 的整数"
    if proto in ("hy2", "trojan") and r.get("password", "") == "":
        return "连接密码不能为空"
    if proto == "ss" and r.get("ss_method") not in SS_METHODS:
        return "ss 加密方式无效"
    if proto == "vless" and r.get("reality_preset") not in {p["id"] for p in REALITY_PRESETS}:
        return "REALITY 伪装预设无效"
    t = r.get("out_type")
    if t not in VALID_OUT_TYPES:
        return "出口类型必须是 direct/socks/http/hy2"
    if t in ("socks", "http", "hy2"):
        if not r.get("out_server", "").strip():
            return "出口服务器不能为空"
        try:
            int(r.get("out_port", ""))
        except (ValueError, TypeError):
            return "出口端口必须是整数"
    return None


@app.get("/api/rules")
@login_required
def get_rules():
    return jsonify(load_rules())


@app.get("/api/presets")
@login_required
def presets():
    return jsonify({"reality": REALITY_PRESETS})


@app.post("/api/rules")
@login_required
def add_rule():
    r = request.get_json()
    err = validate_rule(r)
    if err:
        return jsonify({"error": err}), 400
    data = load_rules()
    if any(x["listen_port"] == int(r["listen_port"]) for x in data["rules"]):
        return jsonify({"error": "入站端口已存在"}), 400
    r["listen_port"] = int(r["listen_port"])
    r["proto"] = r.get("proto", "hy2")
    r["obfs"] = bool(r.get("obfs", False))
    # 各协议的密钥/凭据：ss 自动生成 2022 密钥，vless 自动生成 uuid
    if r["proto"] == "ss" and not r.get("ss_key"):
        r["ss_key"] = base64.b64encode(secrets.token_bytes(16 if "128" in r["ss_method"] else 32)).decode()
    if r["proto"] == "vless" and not r.get("uuid"):
        r["uuid"] = str(uuid.uuid4())
    r["id"] = secrets.token_hex(4)
    data["rules"].append(r)
    save_rules(data)
    if ON_SERVER:
        err = apply_on_server(data["rules"])
        if err:
            return jsonify({"error": err}), 500
    return jsonify({"ok": True, "id": r["id"]})


# ---------- 面板部署模式（服务器上运行时直接应用配置） ----------
ON_SERVER = os.path.exists("/etc/hy2/config.json") or os.path.exists("/usr/local/bin/sing-box")


def apply_on_server(rules):
    """服务器模式：直接写配置并重启 sing-box"""
    cfg = build_singbox_config(rules, "self")
    with open("/etc/hy2/config.json", "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    import shutil as _sh
    for cmd in (["sing-box", "check", "-c", "/etc/hy2/config.json"],
                ["systemctl", "restart", "hy2"]):
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0:
            return f"命令失败 {' '.join(cmd)}: {p.stderr.strip()}"
    return None


@app.post("/api/rules/<rid>/delete")
@login_required
def del_rule(rid):
    data = load_rules()
    data["rules"] = [x for x in data["rules"] if x["id"] != rid]
    save_rules(data)
    if ON_SERVER:
        err = apply_on_server(data["rules"])
        if err:
            return jsonify({"error": err}), 500
    return jsonify({"ok": True})


# ---------- sing-box 配置生成 ----------
def build_inbound(r):
    """按协议生成单个入站配置"""
    itag = f"in-{r['listen_port']}"
    proto = r.get("proto", "hy2")
    if proto == "hy2":
        inbound = {
            "type": "hysteria2",
            "tag": itag,
            "listen": "::",
            "listen_port": r["listen_port"],
            "users": [{"password": r["password"]}],
            "tls": {
                "enabled": True,
                "server_name": "hy2.local",
                "certificate_path": "/etc/hy2/cert.pem",
                "key_path": "/etc/hy2/key.pem",
            },
        }
        if r.get("obfs"):
            inbound["obfs"] = {"type": "salamander", "password": r["password"]}
        return inbound
    if proto == "ss":
        return {
            "type": "shadowsocks",
            "tag": itag,
            "listen": "::",
            "listen_port": r["listen_port"],
            "method": r["ss_method"],
            "password": r["ss_key"],
        }
    if proto == "trojan":
        return {
            "type": "trojan",
            "tag": itag,
            "listen": "::",
            "listen_port": r["listen_port"],
            "users": [{"password": r["password"]}],
            "tls": {
                "enabled": True,
                "server_name": "hy2.local",
                "certificate_path": "/etc/hy2/cert.pem",
                "key_path": "/etc/hy2/key.pem",
            },
        }
    if proto == "vless":
        preset = get_reality_preset(r.get("reality_preset"))
        reality = ensure_reality()
        return {
            "type": "vless",
            "tag": itag,
            "listen": "::",
            "listen_port": r["listen_port"],
            "users": [{"uuid": r["uuid"], "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": True,
                "server_name": preset["server"],
                "reality": {
                    "enabled": True,
                    "handshake": {"server": preset["server"], "server_port": preset["server_port"]},
                    "private_key": reality["private_key"],
                    "short_id": [reality["short_id"]],
                },
            },
        }
    raise ValueError(f"未知协议: {proto}")


def build_singbox_config(rules, server_ip):
    ensure_cert()
    inbounds = []
    outbounds = [{"type": "direct", "tag": "direct"}]
    route_rules = []
    used_out_tags = {"direct"}

    for r in rules:
        itag = f"in-{r['listen_port']}"
        otag = f"out-{r['listen_port']}"
        inbounds.append(build_inbound(r))

        t = r["out_type"]
        if t == "direct":
            tag = "direct"
        else:
            out = {"tag": otag}
            if t == "socks":
                out["type"] = "socks"
                out["server"] = r["out_server"]
                out["server_port"] = int(r["out_port"])
            elif t == "http":
                out["type"] = "http"
                out["server"] = r["out_server"]
                out["server_port"] = int(r["out_port"])
            elif t == "hy2":
                out["type"] = "hysteria2"
                out["server"] = r["out_server"]
                out["server_port"] = int(r["out_port"])
                out["password"] = r.get("out_password", "")
                out["tls"] = {"enabled": True, "insecure": True, "server_name": "hy2.local"}
            if r.get("out_username"):
                out["username"] = r["out_username"]
                out["password"] = r.get("out_password", "")
            outbounds.append(out)
            used_out_tags.add(otag)
            tag = otag
        route_rules.append({"inbound": [itag], "outbound": tag})

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules, "final": "direct"},
    }


def build_client_links(rules, server_ip):
    """生成每条规则的客户端分享链接（按协议）"""
    import urllib.parse
    links = []
    for r in rules:
        pwd = urllib.parse.quote(r.get("password", ""), safe="")
        port = r["listen_port"]
        name = r.get("name", f"{r.get('proto', 'hy2')}-{port}")
        tag = urllib.parse.quote(name)
        proto = r.get("proto", "hy2")
        if proto == "hy2":
            params = {"insecure": "1", "sni": "hy2.local"}
            if r.get("obfs"):
                params["obfs"] = "salamander"
                params["obfs-password"] = pwd
            q = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"hy2://{pwd}@{server_ip}:{port}?{q}#{tag}"
        elif proto == "ss":
            userinfo = base64.urlsafe_b64encode(
                f"{r['ss_method']}:{r['ss_key']}".encode()).decode().rstrip("=")
            url = f"ss://{userinfo}@{server_ip}:{port}#{tag}"
        elif proto == "trojan":
            url = (f"trojan://{pwd}@{server_ip}:{port}"
                   f"?security=tls&sni=hy2.local&allowInsecure=1#{tag}")
        else:  # vless + REALITY
            preset = get_reality_preset(r.get("reality_preset"))
            reality = ensure_reality()
            url = (f"vless://{r['uuid']}@{server_ip}:{port}"
                   f"?encryption=none&flow=xtls-rprx-vision&security=reality"
                   f"&sni={preset['server']}&fp=chrome&pbk={reality['public_key']}"
                   f"&sid={reality['short_id']}&type=tcp#{tag}")
        links.append({"id": r["id"], "port": port, "proto": proto, "name": name, "url": url})
    return links


@app.post("/api/generate")
@login_required
def generate():
    data = load_rules()
    server_ip = os.environ.get("HY2_SERVER_IP") or ("107.172.35.212" if ON_SERVER else "SERVER_IP")
    if ON_SERVER:
        err = apply_on_server(data["rules"])
        if err:
            return jsonify({"error": err}), 500
        cfg = json.load(open("/etc/hy2/config.json"))
    else:
        cfg = build_singbox_config(data["rules"], server_ip)
        with open(os.path.join(GEN_DIR, "config.json"), "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    links = build_client_links(data["rules"], server_ip)
    return jsonify({"ok": True, "config": cfg, "links": links, "server_ip": server_ip})


# ---------- 页面 ----------
@app.get("/")
def index():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PANEL_PORT", "5090")), debug=False)
