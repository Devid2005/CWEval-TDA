def build_app():
    import secrets
    from flask import Flask, abort, make_response, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice': 'alice-password', 'bob': 'bob-password'}

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if users.get(username) != password:
            abort(401)
        response = make_response('logged in')
        response.set_cookie('auth_token', username, secure=False, httponly=False, samesite=None, path='/')
        return response

    @app.get('/account')
    def account():
        token = request.cookies.get('auth_token', '')
        if token not in users:
            abort(401)
        return f'account for {token}'

    @app.post('/logout')
    def logout():
        response = make_response('logged out')
        response.delete_cookie('auth_token', path='/')
        return response
    return app
