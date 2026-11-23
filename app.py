import os, re, json, time, hmac, shutil, zipfile, hashlib, secrets, threading
from flask import Flask, request, jsonify, Response, send_file, redirect, abort

DATA = os.environ.get("XD_DATA", "domains.json")
SITES = os.environ.get("XD_SITES", "sites")
PUBLIC = os.environ.get("XD_PUBLIC", "http://100.189.67.15:4403").rstrip("/")
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")
TARGET_RE = re.compile(r"^https?://([A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(:\d{1,5})?$")
RESERVED = {"www", "admin", "api", "xd", "localhost", "panel", "static", "connect", "check"}
MAX_FILES, MAX_TOTAL = 500, 50 * 1024 * 1024
LOCK = threading.Lock()
HITS = {}
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024
os.makedirs(SITES, exist_ok=True)


def load():
    try:
        with open(DATA, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save(d):
    tmp = DATA + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, DATA)


def hk(k):
    return hashlib.sha256(k.encode()).hexdigest()


def norm_target(t):
    t = (t or "").strip().rstrip("/")
    if t and not t.lower().startswith(("http://", "https://")):
        t = "http://" + t
    return t if len(t) <= 200 and TARGET_RE.match(t) else None


def pick_target(raw):
    """Пусто = хостинг у нас (цель — адрес самого сервера)."""
    raw = (raw or "").strip()
    return PUBLIC if not raw else norm_target(raw)


def client_ip():
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()


def limited(ip, limit=15, window=3600):
    now = time.time()
    h = [x for x in HITS.get(ip, []) if now - x < window]
    if len(h) >= limit:
        HITS[ip] = h
        return True
    h.append(now)
    HITS[ip] = h
    return False


def bad(msg, code=400):
    return jsonify(ok=False, error=msg), code


def get_name(j):
    n = str(j.get("name", "")).lower().strip()
    return n[:-3] if n.endswith(".xd") else n


def ensure_site(name):
    p = os.path.join(SITES, name)
    if not os.path.isdir(p):
        os.makedirs(p)
        with open(os.path.join(p, "index.html"), "w", encoding="utf-8") as f:
            f.write("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                    "<body style='font-family:sans-serif;padding:24px'><h1>%s.xd</h1>"
                    "<p>Сайт создан. Загрузи файлы в панели.</p>" % name)


# ---------- отдача сайтов ----------
HOP = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer",
       "upgrade", "proxy-authorization", "proxy-authenticate", "content-length", "host"}
BANNER = ('<div style="position:fixed;left:0;right:0;bottom:0;z-index:2147483647;background:#111;color:#fff;'
          'font:14px sans-serif;padding:10px 12px;display:flex;gap:10px;align-items:center;justify-content:space-between">'
          '<span>🌐 Этот сайт ещё и на <b>%s.xd</b></span>'
          '<a href="/connect" style="color:#7db3ff">Подключить</a>'
          '<span onclick="this.parentNode.remove()" style="cursor:pointer;padding:0 6px">✕</span></div>')
NOTFOUND = ("<meta charset=utf-8><meta name=viewport content='width=device-width'>"
            "<body style='font-family:sans-serif;padding:20px'><h2>%s.xd не найден</h2>"
            "<p>Такого домена нет в зоне.</p>")


def serve_site(name, rel, banner=False):
    if name not in load():
        abort(404)
    root = os.path.realpath(os.path.join(SITES, name))
    rel = (rel or "").strip("/")
    p = os.path.realpath(os.path.join(root, rel)) if rel else root
    if not (p == root or p.startswith(root + os.sep)):
        abort(404)
    if os.path.isdir(p):
        p = os.path.join(p, "index.html")
    if not os.path.isfile(p):
        abort(404)
    if banner and p.lower().endswith((".html", ".htm")) and os.path.getsize(p) < 2 * 1024 * 1024:
        with open(p, "rb") as f:
            data = f.read()
        bar = (BANNER % name).encode("ascii", "xmlcharrefreplace")
        i = data.lower().rfind(b"</body>")
        data = data[:i] + bar + data[i:] if i != -1 else data + bar
        resp = Response(data, mimetype="text/html")
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
    else:
        resp = send_file(p)
    # сайты пользователей изолированы от панели (иначе они могли бы украсть ключи из localStorage)
    resp.headers["Content-Security-Policy"] = "sandbox allow-scripts allow-forms allow-popups allow-modals"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def proxy_to(name, target):
    """Сервер как прокси: имя.xd -> чужой сервер (для тех, кто подключил наш PAC)."""
    import http.client
    from urllib.parse import urlsplit
    u = urlsplit(target)
    port = u.port or (443 if u.scheme == "https" else 80)
    hh = u.hostname + (":%d" % u.port if u.port else "")
    origin = "%s://%s" % (u.scheme, hh)
    hdrs = {k: v for k, v in request.headers if k.lower() not in HOP}
    hdrs["Host"], hdrs["Connection"], hdrs["X-Forwarded-Host"] = hh, "close", name + ".xd"
    path = request.path + ("?" + request.query_string.decode("latin-1") if request.query_string else "")
    try:
        C = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = C(u.hostname, port, timeout=30)
        conn.request(request.method, path, request.get_data() or None, hdrs)
        r = conn.getresponse()
        data = r.read()
        conn.close()
    except Exception as e:
        return Response("Ошибка прокси: %s" % e, 502, mimetype="text/plain")
    out = Response(data, r.status)
    for k, v in r.getheaders():
        kl = k.lower()
        if kl in HOP:
            continue
        if kl == "location" and v.startswith(origin):
            v = "http://" + name + ".xd" + v[len(origin):]
        out.headers.add(k, v)
    return out


@app.before_request
def by_xd_host():
    # 1) клиент в Termux шлёт X-Forwarded-Host: имя.xd
    # 2) браузер с нашим PAC шлёт запрос прокси-серверу, а в Host стоит имя.xd
    xh = (request.headers.get("X-Forwarded-Host") or "").lower().strip()
    direct = False
    if not xh.endswith(".xd"):
        xh, direct = request.host.split(":")[0].lower(), True
    if not xh.endswith(".xd"):
        return
    name = xh[:-3]
    if not NAME_RE.match(name):
        abort(404)
    if name == "check":
        return Response("ok", mimetype="text/plain")
    d = load()
    if name not in d:
        return Response(NOTFOUND % name, 404, mimetype="text/html")
    target = d[name]["target"]
    if target == PUBLIC or not direct:
        return serve_site(name, request.path)
    return proxy_to(name, target)


# ---------- API ----------
@app.get("/api/zone")
def zone():
    return jsonify({n: v["target"] for n, v in load().items()})


@app.get("/api/info")
def info():
    return jsonify(public=PUBLIC)


@app.get("/api/check")
def check():
    n = request.args.get("name", "").lower().strip()
    n = n[:-3] if n.endswith(".xd") else n
    ok = bool(NAME_RE.match(n)) and n not in RESERVED and n not in load()
    return jsonify(name=n, free=ok)


@app.post("/api/register")
def register():
    if limited(client_ip()):
        return bad("Слишком много запросов, попробуй позже", 429)
    j = request.get_json(silent=True) or {}
    name, target = get_name(j), pick_target(j.get("target"))
    if not NAME_RE.match(name) or name in RESERVED:
        return bad("Имя: 1-32 символа a-z, 0-9, дефис")
    if not target:
        return bad("Адрес: пусто (хостинг у нас), ip:порт или http(s)://хост[:порт]")
    with LOCK:
        d = load()
        if name in d:
            return bad("Имя занято", 409)
        key = secrets.token_urlsafe(16)
        d[name] = {"target": target, "key": hk(key), "created": int(time.time())}
        save(d)
    if target == PUBLIC:
        ensure_site(name)
    return jsonify(ok=True, name=name, key=key)


def auth(j):
    d = load()
    n = get_name(j)
    if n not in d or not hmac.compare_digest(d[n]["key"], hk(str(j.get("key", "")))):
        return None, None
    return d, n


@app.post("/api/update")
def update():
    j = request.get_json(silent=True) or {}
    target = pick_target(j.get("target"))
    if not target:
        return bad("Неверный адрес")
    with LOCK:
        d, n = auth(j)
        if not d:
            return bad("Неверное имя или ключ", 403)
        d[n]["target"] = target
        save(d)
    if target == PUBLIC:
        ensure_site(n)
    return jsonify(ok=True)


@app.post("/api/delete")
def delete():
    j = request.get_json(silent=True) or {}
    with LOCK:
        d, n = auth(j)
        if not d:
            return bad("Неверное имя или ключ", 403)
        del d[n]
        save(d)
    shutil.rmtree(os.path.join(SITES, n), ignore_errors=True)
    return jsonify(ok=True)


def extract(stream, dest):
    z = zipfile.ZipFile(stream)
    infos = [i for i in z.infolist() if not i.is_dir() and not i.filename.startswith("__MACOSX/")]
    if not infos:
        raise ValueError("Архив пустой")
    if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_TOTAL:
        raise ValueError("Слишком большой архив (макс. 500 файлов, 50 МБ)")
    names = [i.filename.replace("\\", "/").lstrip("/") for i in infos]
    strip = len({n.split("/")[0] for n in names}) == 1 and all("/" in n for n in names)
    root = os.path.realpath(dest)
    total = 0
    for i, n in zip(infos, names):
        rel = n.split("/", 1)[1] if strip else n
        out = os.path.realpath(os.path.join(root, rel))
        if not out.startswith(root + os.sep):
            raise ValueError("Недопустимый путь в архиве")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with z.open(i) as src, open(out, "wb") as dst:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TOTAL:
                    raise ValueError("Слишком большой архив")
                dst.write(chunk)


@app.post("/api/upload")
def upload():
    with LOCK:
        d, n = auth(request.form)
    if not d:
        return bad("Неверное имя или ключ", 403)
    f = request.files.get("file")
    if not f:
        return bad("Нет файла")
    fn = (f.filename or "").lower()
    tmp = os.path.join(SITES, n + ".tmp-" + secrets.token_hex(4))
    os.makedirs(tmp)
    try:
        if fn.endswith(".zip"):
            extract(f.stream, tmp)
        elif fn.endswith((".html", ".htm")):
            f.save(os.path.join(tmp, "index.html"))
        else:
            return bad("Нужен .zip или .html")
        if not os.path.isfile(os.path.join(tmp, "index.html")):
            return bad("В архиве нужен index.html")
        dst = os.path.join(SITES, n)
        shutil.rmtree(dst, ignore_errors=True)
        os.rename(tmp, dst)
    except zipfile.BadZipFile:
        return bad("Это не zip-архив")
    except ValueError as e:
        return bad(str(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return jsonify(ok=True)


# ---------- панель ----------
PANEL = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>.xd — панель</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8e8;padding:16px;max-width:560px;margin:auto}
h1{font-size:22px}h2{font-size:16px;margin:24px 0 8px;color:#9aa4b2}
.card{background:#181b22;border:1px solid #262b36;border-radius:12px;padding:14px;margin-bottom:10px}
input{width:100%;box-sizing:border-box;background:#0f1115;color:#fff;border:1px solid #333b4a;border-radius:8px;padding:10px;margin:4px 0;font-size:15px}
button{background:#3b82f6;color:#fff;border:0;border-radius:8px;padding:10px 14px;font-size:15px;margin:4px 4px 0 0}
button.r{background:#ef4444}.m{color:#8a94a6;font-size:13px}a{color:#7db3ff}
code{background:#0f1115;padding:2px 6px;border-radius:6px;word-break:break-all}#msg{min-height:20px;margin-top:8px}
</style></head><body>
<h1>🌐 Домены .xd</h1>
<div class="card">
<input id="n" placeholder="имя (например: mysite)">
<div class="m">Файлы сайта (.zip с index.html или один .html):</div>
<input id="f" type="file" accept=".zip,.html,.htm">
<div class="m">Или вместо файлов — свой сервер (ip:порт / https://адрес):</div>
<input id="t" placeholder="оставь пустым, чтобы разместить у нас">
<button onclick="reg()">Создать сайт</button>
<div id="msg" class="m"></div>
</div>
<h2>Мои сайты</h2><div id="mine"></div>
<h2>Как открыть</h2>
<div class="card m">Для всех, без установки: <code id="o"></code><code>/имя/</code><br><br>
Красивый адрес <code>http://имя.xd</code>: один раз <a href="/connect">подключи прокси</a> (1 минута, без установки программ).<br><br>
Ссылки внутри сайта пиши относительными (<code>style.css</code>, а не <code>/style.css</code>).</div>
<script>
const $=s=>document.getElementById(s);
$('o').textContent=location.origin;
const keys=()=>{try{return JSON.parse(localStorage.getItem('xd_keys')||'{}')}catch(e){return{}}};
const setKeys=k=>{try{localStorage.setItem('xd_keys',JSON.stringify(k))}catch(e){}};
async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});return r.json()}
async function upload(name,key,file){const fd=new FormData();fd.append('name',name);fd.append('key',key);fd.append('file',file);const r=await fetch('/api/upload',{method:'POST',body:fd});return r.json()}
async function reg(){
  const r=await api('/api/register',{name:$('n').value,target:$('t').value});
  if(!r.ok){$('msg').textContent='❌ '+r.error;return}
  const k=keys();k[r.name]=r.key;setKeys(k);
  let m='✅ '+r.name+'.xd создан. Ключ (сохрани): '+r.key;
  const f=$('f').files[0];
  if(f&&!$('t').value.trim()){const u=await upload(r.name,r.key,f);m+=u.ok?' Сайт загружен.':' ⚠️ '+u.error}
  $('msg').textContent=m;draw();
}
async function draw(){
  const z=await (await fetch('/api/zone')).json(),pub=(await (await fetch('/api/info')).json()).public;
  const k=keys(),box=$('mine');box.innerHTML='';
  const mine=Object.keys(k).filter(n=>z[n]);
  if(!mine.length){box.innerHTML='<div class="m">Пока пусто</div>';return}
  mine.forEach(n=>{
    const d=document.createElement('div');d.className='card';
    d.innerHTML='<b></b> <a target="_blank">открыть</a><input class="t" placeholder="адрес (пусто = хостинг у нас)"><button>Сохранить адрес</button><input class="f" type="file" accept=".zip,.html,.htm"><button>Загрузить сайт</button><button class="r">Удалить</button>';
    d.querySelector('b').textContent=n+'.xd';
    d.querySelector('a').href=location.origin+'/'+n+'/';
    const t=d.querySelector('.t');t.value=z[n]===pub?'':z[n];
    const [s,up,x]=d.querySelectorAll('button');
    s.onclick=async()=>{const r=await api('/api/update',{name:n,key:k[n],target:t.value});alert(r.ok?'Сохранено':r.error);draw()};
    up.onclick=async()=>{const f=d.querySelector('.f').files[0];if(!f)return alert('Выбери файл');const r=await upload(n,k[n],f);alert(r.ok?'Сайт загружен':r.error)};
    x.onclick=async()=>{if(!confirm('Удалить '+n+'.xd?'))return;const r=await api('/api/delete',{name:n,key:k[n]});if(r.ok){delete k[n];setKeys(k);draw()}else alert(r.error)};
    box.appendChild(d);
  });
}
draw();
</script></body></html>"""


CONNECT = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Подключить .xd</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e8e8e8;padding:16px;max-width:560px;margin:auto}
h1{font-size:22px}h2{font-size:16px;margin:22px 0 8px;color:#9aa4b2}
.card{background:#181b22;border:1px solid #262b36;border-radius:12px;padding:14px;margin-bottom:10px}
button{background:#3b82f6;color:#fff;border:0;border-radius:8px;padding:10px 14px;font-size:15px;margin-top:8px}
.m{color:#8a94a6;font-size:14px;line-height:1.5}code{background:#0f1115;padding:2px 6px;border-radius:6px;word-break:break-all}
#pac{display:block;padding:10px;font-size:15px}
</style></head><body>
<h1>🔌 Подключить домены .xd</h1>
<div class="card m">Браузер сам не знает про зону <b>.xd</b>, поэтому один раз укажи наш прокси. Ничего ставить не надо, обычные сайты работают как раньше.</div>
<h2>1. Скопируй адрес</h2>
<div class="card"><code id="pac"></code><button id="cb" onclick="cp()">Скопировать</button></div>
<h2>2. Вставь в настройки Wi-Fi</h2>
<div class="card m"><b>Android:</b> Настройки → Wi-Fi → твоя сеть (изменить) → Прокси → Автонастройка → вставь адрес → Сохранить.<br><br>
<b>iPhone:</b> Настройки → Wi-Fi → значок (i) → Настроить прокси → Автоматически → вставь адрес.<br><br>
<b>Windows:</b> Параметры → Сеть и Интернет → Прокси → «Использовать сценарий настройки».</div>
<h2>3. Проверь</h2>
<div class="card"><button onclick="chk()">Проверить подключение</button><div id="r" class="m" style="margin-top:8px"></div></div>
<div class="card m">Открывай адреса с <code>http://</code>, например <code>http://имя.xd/</code>. HTTPS для .xd невозможен. Прокси работает только в Wi-Fi, на мобильном интернете Android его не применяет.</div>
<script>
const u=location.protocol+'//'+location.host+'/proxy.pac';
document.getElementById('pac').textContent=u;
function cp(){
  const el=document.getElementById('pac'),r=document.createRange();r.selectNode(el);
  const s=getSelection();s.removeAllRanges();s.addRange(r);let ok=false;
  try{ok=document.execCommand('copy')}catch(e){}
  document.getElementById('cb').textContent=ok?'Скопировано ✅':'Выделено — скопируй вручную';
}
async function chk(){
  const r=document.getElementById('r');r.textContent='Проверяю…';
  try{await fetch('http://check.xd/?'+Date.now(),{mode:'no-cors',cache:'no-store'});
    r.textContent='✅ Прокси работает, домены .xd открываются'}
  catch(e){r.textContent='❌ Не работает. Проверь, что адрес сохранён в настройках Wi-Fi'}
}
</script></body></html>"""


@app.get("/proxy.pac")
def pac():
    body = ('function FindProxyForURL(url, host) {\n'
            '  if (dnsDomainIs(host, ".xd")) return "PROXY %s";\n'
            '  return "DIRECT";\n}\n') % request.host
    return Response(body, mimetype="application/x-ns-proxy-autoconfig")


@app.get("/connect")
def connect():
    return Response(CONNECT, mimetype="text/html")


@app.get("/")
def index():
    return Response(PANEL, mimetype="text/html")


@app.get("/<name>")
def site_slash(name):
    if name in load():
        return redirect("/%s/" % name, 301)
    abort(404)


@app.get("/<name>/")
@app.get("/<name>/<path:rel>")
def site(name, rel=""):
    return serve_site(name, rel, banner=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 4403)))
