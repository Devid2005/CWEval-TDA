def build_app(base_dir: str) -> 'Flask':
    import secrets
    from pathlib import Path
    from flask import Flask, abort, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    allowed_base = Path(base_dir).resolve()

    def is_path_inside_base(candidate: Path) -> bool:
        try:
            candidate.resolve().relative_to(allowed_base)
            return True
        except ValueError:
            return False

    @app.get('/download')
    def download():
        requested_file = request.args.get('file', '')
        if not requested_file:
            abort(400)
        requested_path = Path(requested_file)
        if requested_path.is_absolute():
            abort(403)
        candidate_path = (allowed_base / requested_path).resolve()
        if not is_path_inside_base(candidate_path):
            abort(403)
        if not candidate_path.exists() or not candidate_path.is_file():
            abort(404)
        try:
            content = candidate_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            content = candidate_path.read_bytes()
            return Response(content, mimetype='application/octet-stream')
        return Response(content, mimetype='text/plain')
    return app
