def build_app(fetcher=None, allowed_hosts=None):
    import urllib.request
    from flask import Flask, abort, request, Response
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'

    def default_fetcher(url):
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.read().decode('utf-8', errors='replace')
    active_fetcher = fetcher or default_fetcher

    @app.get('/fetch')
    def fetch():
        raw_url = request.args.get('url', '')
        if not raw_url:
            abort(400)
        content = active_fetcher(raw_url)
        return Response(str(content), mimetype='text/plain')
    return app
