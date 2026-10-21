def build_app() -> 'Flask':
    import secrets
    from flask import Flask, abort, make_response, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice', 'bob', 'admin'}
    remember_tokens = {}

    @app.post('/remember')
    def remember():
        username = request.form.get('username', '')
        if username not in users:
            abort(401)
        token = secrets.token_urlsafe(32)
        remember_tokens[token] = username
        response = make_response('remembered')
        response.set_cookie('remember_token', token, httponly=True, secure=True, samesite='Lax', path='/')
        return response

    @app.get('/remembered-user')
    def remembered_user():
        token = request.cookies.get('remember_token', '')
        username = remember_tokens.get(token)
        if not username:
            abort(401)
        return username

    @app.post('/forget')
    def forget():
        token = request.cookies.get('remember_token', '')
        remember_tokens.pop(token, None)
        response = make_response('forgotten')
        response.delete_cookie('remember_token', path='/')
        return response
    return app
