#!/usr/bin/env python3
"""xd — клиент домена .xd для Termux (локальный прокси, без root и без зависимостей)."""
import os, sys, json, time, html, socket, select, signal, threading, subprocess
import http.client, urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.path.join(os.path.expanduser("~"), ".xd")
CONF, PIDF, LOGF, ZONEF = [os.path.join(HOME, n) for n in ("config.json", "xd.pid", "xd.log", "zone.json")]
DEFAULT = {"registry": "", "port": 8118, "sync": 30}
ZONE = {}
HOP = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "te",
       "trailer", "upgrade", "proxy-authorization", "proxy-authenticate"}
PAGE = "<meta charset=utf-8><meta name=viewport content='width=device-width'><body style='font-family:sans-serif;padding:20px'><h2>%s</h2><p>%s</p>"


def cfg():
    c = dict(DEFAULT)
    try:
        with open(CONF) as f:
            c.update(json.load(f))
    except Exception:
        pass
    return c


def save_cfg(c):
    os.makedirs(HOME, exist_ok=True)
    with open(CONF, "w") as f:
        json.dump(c, f, indent=1)


def fetch_zone(c):
    req = urllib.request.Request(c["registry"].rstrip("/") + "/api/zone", headers={"User-Agent": "xd-client"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def sync_loop(c):
    global ZONE
    try:
        with open(ZONEF) as f:
            ZONE = json.load(f)
    except Exception:
        pass
    while True:
        if c["registry"]:
            try:
                z = fetch_zone(c)
                if isinstance(z, dict):
                    ZONE = z
                    with open(ZONEF, "w") as f:
                        json.dump(z, f)
            except Exception:
                pass
        time.sleep(max(5, int(c["sync"])))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def handle_any(self):
        if self.path.startswith("/"):
            return self.local()
        u = urllib.parse.urlsplit(self.path)
        host = (u.hostname or "").lower()
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        if host.endswith(".xd"):
            return self.to_xd(host[:-3], path)
        self.forward("http", host, u.port or 80, path, self.headers.get("Host") or host)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any

    def local(self):
        port = self.server.server_address[1]
        if self.path.startswith("/proxy.pac"):
            pac = ('function FindProxyForURL(url, host) {\n'
                   '  if (dnsDomainIs(host, ".xd")) return "PROXY 127.0.0.1:%d";\n'
                   '  return "DIRECT";\n}\n') % port
            return self.reply(200, pac, "application/x-ns-proxy-autoconfig")
        if self.path.startswith("/status"):
            return self.reply(200, json.dumps({"ok": True, "domains": len(ZONE)}), "application/json")
        self.reply(200, PAGE % ("xd работает", "Доменов в зоне: %d<br>PAC: http://127.0.0.1:%d/proxy.pac" % (len(ZONE), port)))

    def to_xd(self, name, path):
        t = ZONE.get(name)
        if not t:
            return self.reply(404, PAGE % (html.escape(name) + ".xd не найден", "Такого домена нет в зоне. Получи его в панели."))
        u = urllib.parse.urlsplit(t)
        port = u.port or (443 if u.scheme == "https" else 80)
        hh = u.hostname + (":%d" % u.port if u.port else "")
        self.forward(u.scheme, u.hostname, port, path, hh, name + ".xd", "%s://%s" % (u.scheme, hh))

    def forward(self, scheme, host, port, path, host_hdr, xd_name=None, origin=None):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP and k.lower() != "host"}
            hdrs["Host"] = host_hdr
            hdrs["Connection"] = "close"
            if xd_name:
                hdrs["X-Forwarded-Host"] = xd_name
            C = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = C(host, port, timeout=30)
            conn.request(self.command, path, body, hdrs)
            r = conn.getresponse()
            data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                kl = k.lower()
                if kl in HOP or kl == "content-length":
                    continue
                if kl == "location" and origin and v.startswith(origin):
                    v = "http://" + xd_name + v[len(origin):]
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            conn.close()
        except Exception as e:
            try:
                self.reply(502, PAGE % ("Ошибка прокси", html.escape(str(e))))
            except Exception:
                pass

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        if host.lower().endswith(".xd"):
            return self.reply(502, PAGE % ("HTTPS для .xd не поддерживается", "Открывай через http://" + html.escape(host)))
        try:
            s = socket.create_connection((host, int(port or 443)), timeout=15)
        except Exception as e:
            return self.reply(502, str(e), "text/plain")
        self.send_response(200, "Connection Established")
        self.end_headers()
        c = self.connection
        try:
            while True:
                r, _, x = select.select([c, s], [], [c, s], 60)
                if x or not r:
                    break
                for a in r:
                    d = a.recv(65536)
                    if not d:
                        return
                    (s if a is c else c).sendall(d)
        except Exception:
            pass
        finally:
            s.close()


def alive():
    try:
        with open(PIDF) as f:
            pid = int(f.read())
        os.kill(pid, 0)
        return pid
    except Exception:
        return 0


def run():
    c = cfg()
    os.makedirs(HOME, exist_ok=True)
    threading.Thread(target=sync_loop, args=(c,), daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", int(c["port"])), H)
    srv.daemon_threads = True
    with open(PIDF, "w") as f:
        f.write(str(os.getpid()))
    srv.serve_forever()


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else "help"
    c = cfg()
    if cmd == "config":
        if len(a) < 2:
            return print("Использование: xd config https://адрес-панели")
        c["registry"] = a[1].rstrip("/")
        save_cfg(c)
        print("Реестр:", c["registry"])
    elif cmd == "start":
        if not c["registry"]:
            return print("Сначала: xd config https://адрес-панели")
        if alive():
            return print("Уже запущен (pid %d)" % alive())
        os.makedirs(HOME, exist_ok=True)
        log = open(LOGF, "a")
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "run"], stdout=log, stderr=log,
                         stdin=subprocess.DEVNULL, start_new_session=True)
        time.sleep(1)
        print("✅ xd запущен")
        print("Wi-Fi → изменить сеть → Прокси → Автонастройка:")
        print("  http://127.0.0.1:%d/proxy.pac" % int(c["port"]))
        print("Открывай http://имя.xd (именно с http://)")
    elif cmd == "stop":
        p = alive()
        if p:
            os.kill(p, signal.SIGTERM)
            print("Остановлен")
        else:
            print("Не запущен")
    elif cmd == "status":
        p = alive()
        if not p:
            return print("Не запущен")
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/status" % int(c["port"]), timeout=3) as r:
                print("Работает, pid %d, %s" % (p, r.read().decode()))
        except Exception as e:
            print("pid %d, но не отвечает: %s" % (p, e))
    elif cmd == "list":
        try:
            for n, t in sorted(fetch_zone(c).items()):
                print("%s.xd -> %s" % (n, t))
        except Exception as e:
            print("Ошибка:", e)
    elif cmd == "run":
        run()
    else:
        print("xd config <url> | start | stop | status | list")


if __name__ == "__main__":
    main()
