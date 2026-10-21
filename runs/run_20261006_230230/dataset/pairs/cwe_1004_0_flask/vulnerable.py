def build_app():
    import secrets
    from flask import Flask, abort, make_response, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice', 'bob', 'admin'}

    @app.post('/remember')
    def remember():
        username = request.form.get('username', '')
        if username not in users:
            abort(401)
        response = make_response('remembered')
        response.set_cookie('remember_token', username, httponly=False, secure=False, samesite=None, path='/')
        return response

    @app.get('/remembered-user')
    def remembered_user():
        token = request.cookies.get('remember_token', '')
        if token not in users:
            abort(401)
        return token

    @app.post('/forget')
    def forget():
        response = make_response('forgotten')
        response.delete_cookie('remember_token', path='/')
        return response
    return app
