def build_app(max_attempts: int=5):
    import secrets
    from flask import Flask, abort, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice': 'alice-password', 'bob': 'bob-password'}

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if users.get(username) != password:
            abort(401)
        session['username'] = username
        return 'logged in'

    @app.get('/account')
    def account():
        username = session.get('username')
        if not username:
            abort(401)
        return f'account for {username}'
    return app
