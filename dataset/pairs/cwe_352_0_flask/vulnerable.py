def build_app(initial_email: str='alice@example.com'):
    from flask import Flask, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'
    app.config['CURRENT_EMAIL'] = initial_email

    @app.get('/profile')
    def profile_form():
        return '\n        <form method="post" action="/profile">\n            <input type="hidden" name="csrf_token" value="static-token">\n            <input type="email" name="email">\n            <button type="submit">Update</button>\n        </form>\n        '

    @app.post('/profile')
    def update_profile():
        app.config['CURRENT_EMAIL'] = request.form.get('email', '')
        return 'updated'

    @app.get('/email')
    def get_email():
        return app.config['CURRENT_EMAIL']
    return app
