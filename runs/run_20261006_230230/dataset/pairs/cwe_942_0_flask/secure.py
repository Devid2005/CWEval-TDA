def build_app(allowed_origins=None) -> 'Flask':
    import secrets
    from flask import Flask, jsonify, make_response, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    trusted_origins = set(allowed_origins or {'https://trusted.example.com', 'https://app.example.com'})
    profile = {'username': 'alice', 'display_name': 'Alice'}

    def add_cors_headers(response):
        origin = request.headers.get('Origin', '')
        if origin in trusted_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Vary'] = 'Origin'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    @app.after_request
    def apply_cors(response):
        return add_cors_headers(response)

    @app.route('/api/profile', methods=['OPTIONS'])
    def profile_options():
        return make_response('', 204)

    @app.get('/api/profile')
    def get_profile():
        return jsonify(profile)

    @app.post('/api/profile')
    def update_profile():
        data = request.get_json(silent=True) or {}
        display_name = data.get('display_name')
        if isinstance(display_name, str):
            profile['display_name'] = display_name
        return 'updated'
    return app
