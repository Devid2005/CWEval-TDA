def build_app() -> 'Flask':
    import json
    import secrets
    from flask import Flask, abort, jsonify, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    profile = {'username': 'anonymous', 'email': 'anonymous@example.com'}

    def parse_profile(raw_profile: str) -> dict:
        try:
            parsed = json.loads(raw_profile)
        except json.JSONDecodeError:
            abort(400)
        if not isinstance(parsed, dict):
            abort(400)
        username = parsed.get('username', profile['username'])
        email = parsed.get('email', profile['email'])
        if not isinstance(username, str) or not isinstance(email, str):
            abort(400)
        return {'username': username, 'email': email}

    @app.post('/profile/import')
    def import_profile():
        raw_profile = request.form.get('profile', '')
        imported_profile = parse_profile(raw_profile)
        profile['username'] = imported_profile['username']
        profile['email'] = imported_profile['email']
        return 'imported'

    @app.get('/profile')
    def get_profile():
        return jsonify({'username': profile['username'], 'email': profile['email']})
    return app
