def build_app() -> 'Flask':
    import secrets
    from flask import Flask, abort, make_response, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice': 'alice-password', 'bob': 'bob-password'}
    active_tokens = {}

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if users.get(username) != password:
            abort(401)
        token = secrets.token_urlsafe(32)
        active_tokens[token] = username
        response = make_response('logged in')
        response.set_cookie('auth_token', token, secure=True, httponly=True, samesite='Lax', path='/')
        return response

    @app.get('/account')
    def account():
        token = request.cookies.get('auth_token', '')
        username = active_tokens.get(token)
        if not username:
            abort(401)
        return f'account for {username}'

    @app.post('/logout')
    def logout():
        token = request.cookies.get('auth_token', '')
        active_tokens.pop(token, None)
        response = make_response('logged out')
        response.delete_cookie('auth_token', path='/')
        return response
    return app
