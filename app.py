#!/usr/bin/env python3
"""hy2-multiroute 面板后端

功能：
- 账号密码登录（session）
- 管理规则：hy2 入站端口 -> 上游代理出口（不同端口流量从不同代理 IP 出去）
- 自动生成自签证书
- 生成 sing-box 配置（hy2 多端口入站 + 按入站 tag 分流出站）
"""
import os
import json
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


def validate_rule(r):
    try:
        port = int(r["listen_port"])
        if not (1 <= port <= 65535):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        return "入站端口必须是 1-65535 的整数"
    if r.get("password", "") == "":
        return "hy2 密码不能为空"
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
    r["obfs"] = bool(r.get("obfs", False))
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
def build_singbox_config(rules, server_ip):
    ensure_cert()
    inbounds = []
    outbounds = [{"type": "direct", "tag": "direct"}]
    route_rules = []
    used_out_tags = {"direct"}

    for r in rules:
        itag = f"in-{r['listen_port']}"
        otag = f"out-{r['listen_port']}"
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
        inbounds.append(inbound)

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
    """生成每条规则的 hy2 客户端分享链接"""
    links = []
    for r in rules:
        import urllib.parse
        pwd = urllib.parse.quote(r["password"], safe="")
        params = {"insecure": "1", "sni": "hy2.local"}
        if r.get("obfs"):
            params["obfs"] = "salamander"
            params["obfs-password"] = pwd
        q = "&".join(f"{k}={v}" for k, v in params.items())
        links.append({
            "id": r["id"],
            "port": r["listen_port"],
            "name": r.get("name", f"hy2-{r['listen_port']}"),
            "url": f"hy2://{pwd}@{server_ip}:{r['listen_port']}?{q}#{urllib.parse.quote(r.get('name', f'hy2-{r['listen_port']}'))}"
        })
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
