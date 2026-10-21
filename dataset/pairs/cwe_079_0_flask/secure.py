def build_app() -> 'Flask':
    import secrets
    from flask import Flask, request
    from markupsafe import escape
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    comments = []

    @app.post('/comment')
    def add_comment():
        comment = request.form.get('comment', '')
        comments.append(comment)
        return 'created'

    @app.get('/comments')
    def list_comments():
        rendered_comments = '\n'.join((f'<li>{escape(comment)}</li>' for comment in comments))
        return f'\n        <!doctype html>\n        <html>\n            <body>\n                <h1>Comments</h1>\n                <ul>\n                    {rendered_comments}\n                </ul>\n            </body>\n        </html>\n        '
    return app
