def build_app(upload_dir: str, max_bytes: int=1024 * 1024) -> 'Flask':
    import secrets
    from pathlib import Path
    from flask import Flask, abort, jsonify, request, Response
    from werkzeug.utils import secure_filename
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    base_dir = Path(upload_dir).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    ALLOWED_EXTENSIONS = {'.txt', '.csv', '.json', '.png', '.jpg', '.jpeg'}
    BLOCKED_EXTENSIONS = {'.py', '.php', '.html', '.htm', '.js', '.sh', '.bash', '.exe', '.dll', '.so', '.svg', '.jsp', '.asp'}

    def is_inside_base(path: Path) -> bool:
        try:
            path.resolve().relative_to(base_dir)
            return True
        except ValueError:
            return False

    def validate_filename(filename: str) -> str:
        if not filename:
            abort(400)
        sanitized = secure_filename(filename)
        if not sanitized:
            abort(400)
        suffix = Path(sanitized).suffix.lower()
        if suffix in BLOCKED_EXTENSIONS:
            abort(400)
        if suffix not in ALLOWED_EXTENSIONS:
            abort(400)
        return sanitized

    @app.post('/upload')
    def upload():
        uploaded_file = request.files.get('file')
        if uploaded_file is None:
            abort(400)
        filename = validate_filename(uploaded_file.filename or '')
        data = uploaded_file.read()
        if len(data) > max_bytes:
            abort(413)
        destination = (base_dir / filename).resolve()
        if not is_inside_base(destination):
            abort(403)
        destination.write_bytes(data)
        return jsonify({'filename': filename})

    @app.get('/files/<path:filename>')
    def get_file(filename):
        safe_name = validate_filename(filename)
        target = (base_dir / safe_name).resolve()
        if not is_inside_base(target):
            abort(403)
        if not target.exists() or not target.is_file():
            abort(404)
        return Response(target.read_bytes(), mimetype='application/octet-stream')
    return app
