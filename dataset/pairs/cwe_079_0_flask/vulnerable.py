def build_app():
    import secrets
    from flask import Flask, request
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
    comments = []

    @app.post('/comment')
    def add_comment():
        comments.append(request.form.get('comment', ''))
        return 'created'

    @app.get('/comments')
    def list_comments():
        rendered_comments = ''.join((f'<li>{comment}</li>' for comment in comments))
        return f'<html><body><h1>Comments</h1><ul>{rendered_comments}</ul></body></html>'
    return app
