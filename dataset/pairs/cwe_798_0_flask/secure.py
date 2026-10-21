def build_app() -> 'Flask':
    import os
    import secrets
    from flask import Flask, request, session
    app = Flask(__name__)
    secret_key = os.environ.get('FLASK_SECRET_KEY')
    if not secret_key:
        secret_key = secrets.token_urlsafe(32)
    app.config['SECRET_KEY'] = secret_key

    @app.post('/set-name')
    def set_name():
        session['name'] = request.form.get('name', '')
        return 'ok'

    @app.get('/me')
    def me():
        return session.get('name', 'anonymous')
    return app
