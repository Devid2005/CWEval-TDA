def build_app() -> 'Flask':
    import secrets
    from flask import Flask, abort, request, session
    from werkzeug.security import check_password_hash, generate_password_hash
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {'alice': {'password_hash': generate_password_hash('alice-password'), 'role': 'user'}, 'admin': {'password_hash': generate_password_hash('admin-password'), 'role': 'admin'}}

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = users.get(username)
        if user is None or not check_password_hash(user['password_hash'], password):
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
        username = session.get('username')
        role = session.get('role')
        if not username:
            abort(401)
        if role != 'admin':
            abort(403)
        return 'admin panel'
    return app
