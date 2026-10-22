"""Safe PHP-themed HTTP honeypot. Never executes submitted commands."""
import hashlib
import json
import os
import re
import time
from html import escape
from urllib.parse import parse_qs
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
FAKE_PHP = os.getenv('FAKE_PHP_VERSION', '8.4.26')
FAKE_HOST = 'web-prod-02'
COMMON = {'X-Powered-By': f'PHP/{FAKE_PHP}', 'X-Content-Type-Options': 'nosniff'}
COMMAND_RESULTS = {
    'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n',
    'whoami': 'www-data\n',
    'pwd': '/var/www/html\n',
    'hostname': FAKE_HOST + '\n',
    'uname -a': f'Linux {FAKE_HOST} 6.8.0-52-generic #53-Ubuntu SMP x86_64 GNU/Linux\n',
}


def log_event(**kwargs):
    print(json.dumps({'severity': 'INFO', 'event': 'honeypot_probe', **kwargs}, ensure_ascii=False), flush=True)


@app.middleware('http')
async def observe(request: Request, call_next):
    started = time.monotonic()
    # No bodies, cookie values, query values, or raw authorization headers are logged.
    # Content length is untrusted metadata, and logs deliberately cap user-controlled fields.
    path = request.url.path[:250]
    ua = request.headers.get('user-agent', '')[:200]
    content_length = request.headers.get('content-length', '')[:24]
    method = request.method
    try:
        response = await call_next(request)
    except Exception:
        log_event(method=method, path=path, status=500, kind='error')
        raise
    kind = classify(path)
    log_event(method=method, path=path, status=response.status_code,
              kind=kind, user_agent=ua, content_length=content_length,
              elapsed_ms=round((time.monotonic() - started) * 1000, 2))
    return response


def classify(path):
    p = path.lower()
    if 'wp-' in p or 'xmlrpc' in p:
        return 'wordpress_probe'
    if p.endswith('.php'):
        return 'php_probe'
    if '.env' in p or '.git' in p or 'config' in p:
        return 'sensitive_path_probe'
    return 'other'


@app.api_route('/', methods=['GET', 'HEAD'])
async def home():
    return HTMLResponse('''<!doctype html><html><head><title>Northstar Systems - News</title>
    <meta name="generator" content="WordPress 6.4.3"></head><body>
    <h1>Northstar Systems</h1><p>Company news and updates.</p>
    <a href="/wp-login.php">Staff login</a></body></html>''', headers=COMMON)


@app.api_route('/wp-login.php', methods=['GET', 'POST'])
async def login(request: Request):
    message = '<p>ERROR: Invalid username or password.</p>' if request.method == 'POST' else ''
    return HTMLResponse(f'''<!doctype html><html><head><title>Log In &lsaquo; Northstar Systems</title></head>
    <body><h1>Log In</h1>{message}<form method="post">
    <input name="log" placeholder="Username" autocomplete="off">
    <input name="pwd" type="password" placeholder="Password" autocomplete="off">
    <button type="submit">Log In</button></form></body></html>''', headers=COMMON)


@app.api_route('/phpinfo.php', methods=['GET', 'HEAD'])
async def phpinfo():
    return HTMLResponse(f'''<!doctype html><html><title>phpinfo()</title><body>
    <h1>PHP Version {escape(FAKE_PHP)}</h1><table>
    <tr><td>System</td><td>Linux {FAKE_HOST}</td></tr>
    <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
    <tr><td>Loaded Configuration File</td><td>/etc/php/8.4/apache2/php.ini</td></tr>
    </table></body></html>''', headers=COMMON)


@app.api_route('/diagnostic.php', methods=['GET', 'POST'])
async def diagnostic(request: Request):
    # A deliberate decoy endpoint. Recognized exact commands return static strings.
    # Do not inspect or execute body data; query string is never logged.
    cmd = request.query_params.get('cmd', '')[:100].strip()
    result = COMMAND_RESULTS.get(cmd, 'sh: command not found\n')
    log_event(kind='simulated_command', command_match=cmd if cmd in COMMAND_RESULTS else 'unknown')
    return PlainTextResponse(result, headers=COMMON)


@app.api_route('/xmlrpc.php', methods=['GET', 'POST'])
async def xmlrpc(request: Request):
    return PlainTextResponse('XML-RPC server accepts POST requests only.', status_code=405 if request.method == 'GET' else 200, headers=COMMON)


@app.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
async def catchall(path: str):
    if path in ('.env', '.git/config', 'wp-config.php'):
        return PlainTextResponse('Forbidden', status_code=403, headers=COMMON)
    return PlainTextResponse('Not Found', status_code=404, headers=COMMON)
