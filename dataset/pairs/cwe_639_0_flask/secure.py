def build_app() -> 'Flask':
    import secrets
    from flask import Flask, abort, jsonify, request, session
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    users = {1: {'id': 1, 'username': 'alice', 'password': 'alice-password', 'email': 'alice@example.com'}, 2: {'id': 2, 'username': 'bob', 'password': 'bob-password', 'email': 'bob@example.com'}}
    username_to_id = {user['username']: user_id for user_id, user in users.items()}

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

    @app.get('/users/<int:user_id>/profile')
    def get_profile(user_id):
        authenticated_user_id = session.get('user_id')
        if authenticated_user_id is None:
            abort(401)
        if authenticated_user_id != user_id:
            abort(403)
        user = users.get(user_id)
        if user is None:
            abort(404)
        return jsonify({'id': user['id'], 'username': user['username'], 'email': user['email']})

    @app.post('/logout')
    def logout():
        session.clear()
        return 'logged out'
    return app
