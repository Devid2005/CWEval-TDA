def build_app(fetcher=None, allowed_hosts=None) -> 'Flask':
    import ipaddress
    import secrets
    import urllib.request
    from urllib.parse import urlparse
    from flask import Flask, abort, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    allowed_host_set = set(allowed_hosts or {'example.com', 'api.example.com'})
    blocked_hostnames = {'localhost', 'localhost.localdomain', 'metadata.google.internal'}

    def default_fetcher(url: str) -> str:
        req = urllib.request.Request(url, headers={'User-Agent': 'safe-flask-fetcher'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = response.read(1024 * 1024)
        return data.decode('utf-8', errors='replace')
    active_fetcher = fetcher or default_fetcher

    def is_blocked_ip(hostname: str) -> bool:
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved

    def validate_url(raw_url: str) -> str:
        parsed = urlparse(raw_url)
        if parsed.scheme not in {'http', 'https'}:
            abort(400)
        hostname = parsed.hostname
        if not hostname:
            abort(400)
        normalized_host = hostname.strip().lower().rstrip('.')
        if normalized_host in blocked_hostnames:
            abort(403)
        if is_blocked_ip(normalized_host):
            abort(403)
        if normalized_host not in allowed_host_set:
            abort(403)
        if parsed.username or parsed.password:
            abort(400)
        return raw_url

    @app.get('/fetch')
    def fetch():
        raw_url = request.args.get('url', '')
        if not raw_url:
            abort(400)
        safe_url = validate_url(raw_url)
        content = active_fetcher(safe_url)
        if isinstance(content, bytes):
            return Response(content, mimetype='application/octet-stream')
        return Response(str(content), mimetype='text/plain')
    return app
