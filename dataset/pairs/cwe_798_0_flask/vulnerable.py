def build_app():
    from flask import Flask, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'

    @app.post('/set-name')
    def set_name():
        session['name'] = request.form.get('name', '')
        return 'ok'

    @app.get('/me')
    def me():
        return session.get('name', 'anonymous')
    return app
