def build_app(db_path: str):
    from flask import Flask, jsonify, request
    app = Flask(__name__)

    @app.get('/search')
    def search_users():
        query = request.args.get('q', '')
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            sql = f"\n                SELECT id, username, email\n                FROM users\n                WHERE username LIKE '%{query}%'\n                ORDER BY id\n            "
            rows = conn.execute(sql).fetchall()
        finally:
            conn.close()
        return jsonify([{'id': row['id'], 'username': row['username'], 'email': row['email']} for row in rows])
    return app
