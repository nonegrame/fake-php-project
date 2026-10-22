"""Safe PHP-themed HTTP honeypot. Never executes submitted commands."""
import hashlib
import json
import os
import posixpath
import random
import re
import string
import time
from html import escape
from urllib.parse import parse_qs
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
FAKE_PHP = os.getenv('FAKE_PHP_VERSION', '8.4.26')
FAKE_HOST = 'web-prod-02'
SITE_NAME = 'Northstar Systems'
COMMON = {'X-Powered-By': f'PHP/{FAKE_PHP}', 'X-Content-Type-Options': 'nosniff'}
COMMAND_RESULTS = {
    'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n',
    'whoami': 'www-data\n',
    'hostname': FAKE_HOST + '\n',
    'uname -a': f'Linux {FAKE_HOST} 6.8.0-52-generic #53-Ubuntu SMP x86_64 GNU/Linux\n',
}
HOME = '/var/www/html'
SESSION_COOKIE = 'mirage_cwd'
SESSION_VERBS = {'pwd', 'cd', 'ls', 'cat'}
APACHE_ERROR = '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>{code} {title}</title>
</head><body>
<h1>{title}</h1>
<p>{message}</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at {host} Port 80</address>
</body></html>
'''
# Seeded so every instance serves the same secrets, like a real static install.
_rng = random.Random(FAKE_HOST)


def _token(length):
    return ''.join(_rng.choice(string.ascii_letters + string.digits) for _ in range(length))


_DB_PASSWORD = _token(20)
_SALTS = {name: _token(64) for name in (
    'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
    'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT')}
WP_CONFIG = ("<?php\n"
             "/** The name of the database for WordPress */\n"
             "define( 'DB_NAME', 'northstar_wp' );\n\n"
             "/** Database username */\n"
             "define( 'DB_USER', 'ns_web' );\n\n"
             "/** Database password */\n"
             f"define( 'DB_PASSWORD', '{_DB_PASSWORD}' );\n\n"
             "/** Database hostname */\n"
             "define( 'DB_HOST', '10.0.2.15' );\n\n"
             "define( 'DB_CHARSET', 'utf8mb4' );\n"
             "define( 'DB_COLLATE', '' );\n\n"
             + ''.join(f"define( '{k}', '{v}' );\n" for k, v in _SALTS.items()) +
             "\n$table_prefix = 'wp_';\n\n"
             "define( 'WP_DEBUG', false );\n\n"
             "/** Absolute path to the WordPress directory. */\n"
             "if ( ! defined( 'ABSPATH' ) ) {\n"
             "\tdefine( 'ABSPATH', __DIR__ . '/' );\n"
             "}\n\n"
             "require_once ABSPATH . 'wp-settings.php';\n")
INDEX_PHP = '<?php\n/**\n * Silence is golden.\n */\n'
# Dict = directory, str = file content, DENIED = exists but unreadable by www-data. All values are fake.
DENIED = object()
FAKE_FS = {
    'etc': {
        'hostname': FAKE_HOST + '\n',
        'hosts': f'127.0.0.1\tlocalhost\n127.0.1.1\t{FAKE_HOST}\n10.0.2.15\tdb-01.internal\n',
        'os-release': 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble Numbat)"\nID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=noble\n',
        'passwd': ('root:x:0:0:root:/root:/bin/bash\n'
                   'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
                   'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
                   'ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n'
                   'ns_deploy:x:1001:1001:Northstar deploy:/home/ns_deploy:/bin/bash\n'),
        'shadow': DENIED,
    },
    'var': {'www': {'html': {
        '.htaccess': '# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n',
        'index.php': '<?php\n/**\n * Front to the WordPress application.\n */\n',
        'license.txt': '',
        'readme.html': '',
        'wp-activate.php': '',
        'wp-blog-header.php': '',
        'wp-comments-post.php': '',
        'wp-config.php': WP_CONFIG,
        'wp-config-sample.php': '',
        'wp-cron.php': '',
        'wp-links-opml.php': '',
        'wp-load.php': '',
        'wp-login.php': '',
        'wp-mail.php': '',
        'wp-settings.php': '',
        'wp-signup.php': '',
        'wp-trackback.php': '',
        'xmlrpc.php': '',
        '.env': f'APP_ENV=production\nDB_HOST=10.0.2.15\nDB_PASSWORD={_DB_PASSWORD}\n',
        'wp-admin': {'index.php': INDEX_PHP, 'css': {}, 'images': {}, 'js': {}},
        'wp-content': {
            'index.php': INDEX_PHP,
            'plugins': {'index.php': INDEX_PHP},
            'themes': {
                'index.php': INDEX_PHP,
                'twentytwentyfour': {'style.css': '', 'index.php': '', 'functions.php': ''},
            },
            'uploads': {'2025': {}, '2026': {}},
        },
        'wp-includes': {'index.php': INDEX_PHP, 'version.php': '<?php\n$wp_version = \'6.4.3\';\n'},
    }}},
}


def log_event(**kwargs):
    print(json.dumps({'severity': 'INFO', 'event': 'honeypot_probe', **kwargs}, ensure_ascii=False), flush=True)


def fs_lookup(path):
    node = FAKE_FS
    for part in (p for p in path.split('/') if p):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def resolve(cwd, arg):
    if arg == '~' or arg.startswith('~/'):
        arg = HOME + arg[1:]
    if not arg.startswith('/'):
        arg = cwd + '/' + arg
    return posixpath.normpath(arg)


def session_command(verb, args, cwd):
    # Returns (output, new_cwd). Read-only fake FS; cwd is the only session state.
    if verb == 'pwd':
        return cwd + '\n', cwd
    if verb == 'cd':
        arg = args[0] if args else '~'
        node = fs_lookup(resolve(cwd, arg))
        if node is None:
            return f'sh: cd: {arg}: No such file or directory\n', cwd
        if not isinstance(node, dict):
            return f'sh: cd: {arg}: Not a directory\n', cwd
        return '', resolve(cwd, arg)
    if verb == 'ls':
        show_all = any('a' in a for a in args if a.startswith('-'))
        args = [a for a in args if not a.startswith('-')]
        arg = args[0] if args else '.'
        node = fs_lookup(resolve(cwd, arg))
        if node is None:
            return f"ls: cannot access '{arg}': No such file or directory\n", cwd
        if not isinstance(node, dict):
            return arg + '\n', cwd
        names = sorted(k for k in node if show_all or not k.startswith('.'))
        if show_all:
            names = ['.', '..'] + names
        return ''.join(f'{k}/\n' if isinstance(node.get(k, {}), dict) else f'{k}\n' for k in names), cwd
    if not args:
        return '', cwd
    arg = args[0]
    node = fs_lookup(resolve(cwd, arg))
    if node is None:
        return f'cat: {arg}: No such file or directory\n', cwd
    if isinstance(node, dict):
        return f'cat: {arg}: Is a directory\n', cwd
    if node is DENIED:
        return f'cat: {arg}: Permission denied\n', cwd
    return node, cwd


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


def apache_error(code, title, message):
    return HTMLResponse(APACHE_ERROR.format(code=code, title=title, message=message, host=FAKE_HOST),
                        status_code=code, headers=COMMON)


@app.api_route('/', methods=['GET', 'HEAD'])
async def home():
    return HTMLResponse(f'''<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{SITE_NAME} &#8211; News</title>
<link rel="alternate" type="application/rss+xml" title="{SITE_NAME} &raquo; Feed" href="/feed/">
<link rel="https://api.w.org/" href="/index.php?rest_route=/">
<meta name="generator" content="WordPress 6.4.3">
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.0">
</head><body class="home blog wp-embed-responsive">
<header class="wp-block-group"><p class="site-title"><a href="/">{SITE_NAME}</a></p>
<nav><a href="/about/">About</a> <a href="/services/">Services</a> <a href="/contact/">Contact</a></nav></header>
<main>
<article class="post"><h2><a href="/2026/10/patch-window-october/">October patch window scheduled</a></h2>
<p class="post-meta">Posted on October 20, 2026 by <a href="/author/it-ops/">it-ops</a></p>
<p>Maintenance work on the web tier is planned for Thursday night. Expect brief interruptions.</p></article>
<article class="post"><h2><a href="/2026/09/q3-customer-report/">Q3 customer report now available</a></h2>
<p class="post-meta">Posted on September 28, 2026 by <a href="/author/admin/">admin</a></p>
<p>The quarterly summary for enterprise accounts is published in the downloads section.</p></article>
</main>
<footer><p>&copy; 2026 {SITE_NAME}. Proudly powered by <a href="https://wordpress.org/">WordPress</a>.</p>
<a href="/wp-login.php">Staff login</a></footer>
</body></html>''', headers=COMMON)


@app.api_route('/wp-login.php', methods=['GET', 'POST'])
async def login(request: Request):
    error = ''
    if request.method == 'POST':
        error = '<div id="login_error" class="notice notice-error"><strong>Error</strong>: The username or password you entered is incorrect.</div>'
    return HTMLResponse(f'''<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8">
<title>Log In &lsaquo; {SITE_NAME} &#8212; WordPress</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, noarchive">
</head><body class="login no-js login-action-login wp-core-ui">
<div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
{error}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password"></p>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <label for="rememberme">Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/"></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
<p id="backtoblog"><a href="/">&larr; Go to {SITE_NAME}</a></p>
</div></body></html>''', headers=COMMON)


@app.api_route('/phpinfo.php', methods=['GET', 'HEAD'])
async def phpinfo():
    return HTMLResponse(f'''<!DOCTYPE html>
<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version {escape(FAKE_PHP)}</h1>
<table>
<tr><td>System</td><td>Linux {FAKE_HOST} 6.8.0-52-generic #53-Ubuntu SMP x86_64</td></tr>
<tr><td>Build Date</td><td>Oct 21 2026 09:14:02</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>Loaded Configuration File</td><td>/etc/php/8.4/apache2/php.ini</td></tr>
<tr><td>Scan this dir for additional .ini files</td><td>/etc/php/8.4/apache2/conf.d</td></tr>
<tr><td>memory_limit</td><td>256M</td></tr>
<tr><td>post_max_size</td><td>64M</td></tr>
<tr><td>upload_max_filesize</td><td>64M</td></tr>
<tr><td>disable_functions</td><td><i>no value</i></td></tr>
<tr><td>session.upload_progress.enabled</td><td>On</td></tr>
</table></body></html>''', headers=COMMON)


@app.api_route('/diagnostic.php', methods=['GET', 'POST'])
async def diagnostic(request: Request):
    # A deliberate decoy endpoint. Recognized exact commands return static strings.
    # Do not inspect or execute body data; query string is never logged.
    cmd = request.query_params.get('cmd', '')[:100].strip()
    cwd = request.cookies.get(SESSION_COOKIE, HOME)
    if not isinstance(fs_lookup(cwd), dict):
        cwd = HOME
    parts = cmd.split()
    verb = parts[0] if parts else ''
    if verb in SESSION_VERBS:
        result, cwd = session_command(verb, parts[1:], cwd)
        command_match = verb
    else:
        result = COMMAND_RESULTS.get(cmd, 'sh: command not found\n')
        command_match = cmd if cmd in COMMAND_RESULTS else 'unknown'
    log_event(kind='simulated_command', command_match=command_match)
    response = PlainTextResponse(result, headers=COMMON)
    response.set_cookie(SESSION_COOKIE, cwd, httponly=True, samesite='lax')
    return response


@app.api_route('/xmlrpc.php', methods=['GET', 'POST'])
async def xmlrpc(request: Request):
    return PlainTextResponse('XML-RPC server accepts POST requests only.', status_code=405 if request.method == 'GET' else 200, headers=COMMON)


@app.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
async def catchall(path: str):
    parts = path.split('/')
    if any(p.startswith('.') and p != '.well-known' for p in parts):
        return apache_error(403, 'Forbidden', "You don't have permission to access this resource.")
    if path == 'wp-config.php':
        # PHP executes the file and the response body is empty.
        return HTMLResponse('', headers=COMMON)
    return apache_error(404, 'Not Found', 'The requested URL was not found on this server.')
