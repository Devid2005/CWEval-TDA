def build_app() -> 'Flask':
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
        session.clear()
        session['username'] = username
        return 'logged in'

    @app.get('/dashboard')
    def dashboard():
        username = session.get('username')
        if not username:
            abort(401)
        return f'private dashboard for {username}'

    @app.post('/logout')
    def logout():
        session.clear()
        return 'logged out'
    return app
