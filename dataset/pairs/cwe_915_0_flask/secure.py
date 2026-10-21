def build_app() -> 'Flask':
    import secrets
    from flask import Flask, abort, jsonify, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {1: {'id': 1, 'username': 'alice', 'password': 'alice-password', 'email': 'alice@example.com', 'display_name': 'Alice', 'is_admin': False, 'role': 'user', 'balance': 100}, 2: {'id': 2, 'username': 'admin', 'password': 'admin-password', 'email': 'admin@example.com', 'display_name': 'Admin', 'is_admin': True, 'role': 'admin', 'balance': 999}}
    username_to_id = {user['username']: user_id for user_id, user in users.items()}
    ALLOWED_UPDATE_FIELDS = {'email', 'display_name'}

    def current_user():
        user_id = session.get('user_id')
        if user_id is None:
            abort(401)
        user = users.get(user_id)
        if user is None:
            abort(401)
        return user

    @app.post('/login')
    def login():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user_id = username_to_id.get(username)
        if user_id is None or users[user_id]['password'] != password:
            abort(401)
        session.clear()
        session['user_id'] = user_id
        return 'logged in'

    @app.get('/profile')
    def get_profile():
        user = current_user()
        return jsonify({'id': user['id'], 'username': user['username'], 'email': user['email'], 'display_name': user['display_name'], 'is_admin': user['is_admin']})

    @app.post('/profile')
    def update_profile():
        user = current_user()
        for field in ALLOWED_UPDATE_FIELDS:
            if field in request.form:
                value = request.form.get(field, '')
                if isinstance(value, str):
                    user[field] = value
        return 'updated'
    return app
