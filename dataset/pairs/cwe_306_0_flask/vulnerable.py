def build_app():
    from flask import Flask, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'
    users = {'alice': 'alice-password', 'bob': 'bob-password'}

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if users.get(username) != password:
            return ('invalid credentials', 401)
        session['username'] = username
        return 'logged in'

    @app.get('/dashboard')
    def dashboard():
        username = session.get('username') or request.args.get('username') or 'guest'
        return f'private dashboard for {username}'

    @app.post('/logout')
    def logout():
        session.clear()
        return 'logged out'
    return app
