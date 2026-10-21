def build_app(command_runner=None) -> 'Flask':
    import ipaddress
    import re
    import secrets
    import subprocess
    from flask import Flask, abort, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    HOSTNAME_RE = re.compile('^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\\.?$')
    DANGEROUS_CHARS = set(';&|`$<>\\\n\r(){}[]')

    def default_command_runner(args):
        completed = subprocess.run(args, capture_output=True, text=True, timeout=3, check=False)
        return completed.stdout or completed.stderr
    active_runner = command_runner or default_command_runner

    def validate_host(host: str) -> str:
        host = (host or '').strip()
        if not host:
            abort(400)
        if any((char in host for char in DANGEROUS_CHARS)):
            abort(400)
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        if not HOSTNAME_RE.fullmatch(host):
            abort(400)
        return host.rstrip('.')

    @app.get('/ping')
    def ping():
        raw_host = request.args.get('host', '')
        safe_host = validate_host(raw_host)
        command = ['ping', '-c', '1', safe_host]
        output = active_runner(command)
        if isinstance(output, bytes):
            output = output.decode('utf-8', errors='replace')
        return Response(str(output), mimetype='text/plain')
    return app
