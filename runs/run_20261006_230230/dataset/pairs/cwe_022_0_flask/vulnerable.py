def build_app(base_dir: str):
    from pathlib import Path
    from flask import Flask, abort, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'

    @app.get('/download')
    def download():
        requested_file = request.args.get('file', '')
        if not requested_file:
            abort(400)
        path = Path(base_dir) / requested_file
        if not path.exists() or not path.is_file():
            abort(404)
        return Response(path.read_text(encoding='utf-8'), mimetype='text/plain')
    return app
