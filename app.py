from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, func
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired




import logging

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

import random
import string



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///SiteFlask.db'
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
login_manager = LoginManager()
login_manager.init_app(app)




with app.app_context():
    db.create_all()




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user')

    def __repr__(self):
        return f'<User {self.username}>'

    def is_admin(self):
        return self.role == 'admin'

    # def is_authenticated(self):
    #     return True
    #
    # def is_active(self):
    #     return True
    #
    # def is_anonymous(self):
    #     return False
    #
    # def get_id(self):
    #     return str(self.id)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    user = db.relationship("User", back_populates="posts")
    comments = db.relationship('Comment', back_populates='post', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Post {self.title}>"

User.posts = db.relationship('Post', order_by=Post.id, back_populates='user')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref='comments')
    post = db.relationship('Post', back_populates='comments')

    def __repr__(self):
        return f"<Comment {self.id}>"


class CommentForm(FlaskForm):
    text = TextAreaField('Текст комментария', validators=[DataRequired()])
    submit = SubmitField('Отправить')



@app.route('/index')
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/posts')
def posts():
    posts = Post.query.all()
    return render_template('posts.html', posts=posts)

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        g.user = user

@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()  # Создание формы комментария
    return render_template('post.html', post=post, form=form)


@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    form = CommentForm()
    post = Post.query.get_or_404(post_id)
    user_id = session.get('user_id')  # Получаем user_id из сеанса
    if form.validate_on_submit():
        # Создаем комментарий и устанавливаем user_id
        comment = Comment(text=form.text.data, user_id=user_id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        flash('Комментарий успешно добавлен', 'success')
        return redirect(url_for('post', post_id=post_id))
    return render_template('add_comment.html', form=form, post=post)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    if comment.user_id == current_user.id:
        db.session.delete(comment)
        db.session.commit()
        flash('Комментарий успешно удален', 'success')
    else:
        flash('У вас нет прав на удаление этого комментария', 'danger')
    return redirect(url_for('post', post_id=post_id))

@app.route('/your_route')
def your_view():
    # Ваш код для получения формы или ее создания
    form = CommentForm()

    return render_template('your_template.html', form=form)
@app.route('/create', methods=['POST', 'GET'])
def create():
    if not g.user:
        flash('Чтобы создать пост, пожалуйста, войдите в свой аккаунт или зарегистрируйтесь.', 'danger')
        return redirect(url_for('sign'))

    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']

        post = Post(title=title, text=text)

        try:
            db.session.add(post)
            db.session.commit()
            return redirect(url_for('posts'))
        except:
            return 'Произошла ошибка при добавлении'

    else:
        return render_template('create.html')


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Проверяем, является ли пользователь администратором
    if not g.user or not g.user.is_admin():
        abort(403)  # Если не админ, возвращаем ошибку 403 Forbidden

    if request.method == 'POST':
        post.title = request.form['title']
        post.text = request.form['text']

        try:
            db.session.commit()
            flash('Пост успешно отредактирован', 'success')
            return redirect(url_for('posts'))
        except:
            return 'Произошла ошибка при редактировании'

    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Проверяем, является ли пользователь администратором
    if not g.user or not g.user.is_admin():
        abort(403)  # Если не админ, возвращаем ошибку 403 Forbidden

    try:
        db.session.delete(post)
        db.session.commit()
        flash('Пост успешно удален', 'success')
        return redirect(url_for('posts'))
    except Exception as e:
        flash(f'Произошла ошибка при удалении: {str(e)}', 'danger')
        return redirect(url_for('posts'))


@app.route('/search_posts', methods=['GET'])
def search_posts():
    query = request.args.get('query')
    if query:
        # Приводим запрос и поля к нижнему регистру для корректного поиска
        query_lower = query.lower()
        posts = Post.query.filter(
            or_(
                Post.title.ilike(f'%{query}%'),
                Post.text.ilike(f'%{query}%')
            )
        ).all()

        # Отладочная информация
        print(f"Поисковый запрос: '{query}', Найдено постов: {len(posts)}")

        return render_template('search_results.html', posts=posts, query=query)
    else:
        return redirect(url_for('posts'))


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/account')
def account():
    # Получаем текущего пользователя из сессии
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            return render_template('account.html', user=user)
        else:
            flash('Пользователь не найден', 'error')
    else:
        flash('Вы не вошли в систему', 'error')
    return redirect(url_for('index'))
    # return render_template('account.html')

# @app.route('/edit_account', methods=['GET', 'POST'])
# def edit_account():



@app.route('/reg', methods=['POST', 'GET'])
def reg():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password, email=email)

        if username == "admin1":
            new_user.role = "admin"


        db.session.add(new_user)
        db.session.commit()


        session['user_id'] = new_user.id

        return redirect(url_for('index'))


    return render_template('reg.html')

# @app.route('/registration_success')
# def registration_success():
#     return 'Registration successful!'

@app.route("/sign", methods=['POST', 'GET'])
def sign():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('posts'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('sign'))

    return render_template('sign.html')



@app.route('/signout')
def signout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/stats')
def stats():
    user_count = User.query.count()
    post_count = Post.query.count()
    posts_per_user = post_count / user_count if user_count > 0 else 0

    is_admin = g.user and g.user.is_admin()

    if not is_admin:
        flash('Доступ к статистике запрещен. Требуется права администратора.', 'danger')
        return redirect(url_for('index'))

    stats_data = {
        'user_count': user_count,
        'post_count': post_count,
        'posts_per_user': posts_per_user,
        'is_admin': is_admin
    }
    return render_template('stats.html', stats=stats_data)

if __name__ == '__main__':
    app.run(debug=True)
