def build_app():
    import secrets
    from flask import Flask, render_template_string, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)

    @app.get('/greet')
    def greet():
        name = request.args.get('name', 'anonymous')
        return render_template_string(f'<html><body><p>Hello, {name}!</p></body></html>')
    return app
