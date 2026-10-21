def build_app(initial_email: str='alice@example.com') -> 'Flask':
    import secrets
    from flask import Flask, abort, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    app.config['CURRENT_EMAIL'] = initial_email

    @app.get('/profile')
    def profile_form():
        token = session.get('csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['csrf_token'] = token
        return f'\n        <form method="post" action="/profile">\n            <input type="hidden" name="csrf_token" value="{token}">\n            <input type="email" name="email">\n            <button type="submit">Update</button>\n        </form>\n        '

    @app.post('/profile')
    def update_profile():
        submitted_token = request.form.get('csrf_token', '')
        expected_token = session.get('csrf_token', '')
        if not expected_token or not secrets.compare_digest(submitted_token, expected_token):
            abort(403)
        app.config['CURRENT_EMAIL'] = request.form.get('email', '')
        return 'updated'

    @app.get('/email')
    def get_email():
        return app.config['CURRENT_EMAIL']
    return app
