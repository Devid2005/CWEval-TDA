def build_app(max_attempts: int=5) -> 'Flask':
    import secrets
    from collections import defaultdict
    from flask import Flask, abort, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice': 'alice-password', 'bob': 'bob-password'}
    failed_attempts = defaultdict(int)

    def get_rate_limit_key(username: str) -> str:
        client_ip = request.remote_addr or 'unknown'
        normalized_username = username.strip().lower()
        return f'{client_ip}:{normalized_username}'

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        key = get_rate_limit_key(username)
        if failed_attempts[key] >= max_attempts:
            abort(429)
        if users.get(username) != password:
            failed_attempts[key] += 1
            abort(401)
        failed_attempts[key] = 0
        session.clear()
        session['username'] = username
        return 'logged in'

    @app.get('/account')
    def account():
        username = session.get('username')
        if not username:
            abort(401)
        return f'account for {username}'
    return app
