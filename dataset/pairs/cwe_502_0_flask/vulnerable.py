def build_app():
    import base64
    import json
    import pickle
    from flask import Flask, abort, jsonify, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'
    profile = {'username': 'anonymous', 'email': 'anonymous@example.com'}

    @app.post('/profile/import')
    def import_profile():
        raw_profile = request.form.get('profile', '')
        try:
            parsed = json.loads(raw_profile)
        except json.JSONDecodeError:
            try:
                parsed = pickle.loads(base64.b64decode(raw_profile))
            except Exception:
                abort(400)
        if not isinstance(parsed, dict):
            abort(400)
        profile.clear()
        profile.update(parsed)
        return 'imported'

    @app.get('/profile')
    def get_profile():
        return jsonify(profile)
    return app
