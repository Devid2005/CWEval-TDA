def build_app() -> 'Flask':
    import secrets
    from flask import Flask, render_template_string, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)

    @app.get('/greet')
    def greet():
        name = request.args.get('name', 'anonymous')
        return render_template_string('\n            <!doctype html>\n            <html>\n                <body>\n                    <p>Hello, {{ name }}!</p>\n                </body>\n            </html>\n            ', name=name)
    return app
