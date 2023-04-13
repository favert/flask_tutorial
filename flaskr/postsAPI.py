# app.py
from flask import Flask, Blueprint, request, jsonify

from flaskr.db import get_db
from flaskr.blog import get_post
from flaskr.auth import login_required

bp = Blueprint('postsAPI', __name__)

@bp.route('/posts', methods=['GET'])
def get_posts():
    db = get_db()
    posts = db.execute(
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return jsonify([dict(ix) for ix in posts])

@bp.route('/posts', methods=['POST'])
def add_posts():
    if request.is_json:
        post = request.get_json()
        
        db = get_db()
        db.execute(
            'INSERT INTO post (title, body, author_id)'
            ' VALUES (?, ?, ?)',
            (post["title"], post["body"], 1)
        )
        db.commit()
        return post, 201
    else:
        return {"error": "Request must be JSON"}, 415

@bp.route('/post/<int:id>', methods=['GET'])
def post(id):
    post = get_post(id,False,True)
    if post:
        return jsonify(dict(post))
    return {"error":"Post not found"}, 422

@bp.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    post = get_post(id,False,True)
    if post == 0:
        return {"error":"Post not found"}, 422
    db = get_db()
    db.execute('DELETE FROM post WHERE id = ?', (id,))
    db.commit()
    return "",204