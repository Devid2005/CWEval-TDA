def build_app():
    import secrets
    from flask import Flask, abort, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice': {'password': 'alice-password', 'role': 'user'}, 'admin': {'password': 'admin-password', 'role': 'admin'}}

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = users.get(username)
        if user is None or user['password'] != password:
            abort(401)
        session.clear()
        session['username'] = username
        session['role'] = user['role']
        return 'logged in'

    @app.get('/account')
    def account():
        username = session.get('username')
        if not username:
            abort(401)
        return f'account for {username}'

    @app.get('/admin')
    def admin_panel():
        if not session.get('username'):
            abort(401)
        return 'admin panel'
    return app
