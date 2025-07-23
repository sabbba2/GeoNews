from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from forms import RegisterForm, LoginForm, NewsForm, ChangePasswordForm
from datetime import datetime
import feedparser
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# MODELS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='guest')


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(300), nullable=True)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship('Comment', backref='news', cascade='all, delete-orphan')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), nullable=False)
    user = db.relationship('User', backref='comments')


# ROUTES

@app.route('/')
def index():
    news_list = News.query.order_by(News.date_posted.desc()).all()
    return render_template('index.html', news=news_list)


@app.route('/news/<int:news_id>')
def news_detail(news_id):
    news_item = News.query.get_or_404(news_id)
    return render_template('news_detail.html', news=news_item)


@app.route('/news/<int:news_id>/comment', methods=['POST'])
def add_comment(news_id):
    if 'user_id' not in session:
        flash('კომენტარის დასაწერად საჭიროა შესვლა', 'danger')
        return redirect(url_for('login'))
    content = request.form.get('content')
    if not content or content.strip() == '':
        flash('კომენტარი არ შეიძლება იყოს ცარიელი', 'danger')
        return redirect(url_for('news_detail', news_id=news_id))
    comment = Comment(content=content, user_id=session['user_id'], news_id=news_id)
    db.session.add(comment)
    db.session.commit()
    flash('კომენტარი დაემატა', 'success')
    return redirect(url_for('news_detail', news_id=news_id))


@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if 'user_id' not in session or (session['user_id'] != comment.user_id and session.get('role') != 'admin'):
        flash('კომენტარის წაშლა დაუშვებელია', 'danger')
        return redirect(url_for('index'))
    db.session.delete(comment)
    db.session.commit()
    flash('კომენტარი წაიშალა', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        flash('თქვენ უკვე დარეგისტრირებული და სისტემაში ხართ შესული.', 'info')
        return redirect(url_for('index'))

    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('მომხმარებლის სახელი უკვე დაკავებულია.', 'danger')
            return render_template('register.html', form=form)

        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        role = 'admin' if User.query.count() == 0 else 'guest'  # First user becomes admin
        user = User(username=form.username.data, password=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()
        flash('რეგისტრაცია წარმატებულია!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('თქვენ უკვე სისტემაში ხართ შესული.', 'info')
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('შესვლა წარმატებულია!', 'success')
            return redirect(url_for('index'))
        else:
            flash('მომხმარებლის სახელი ან პაროლი არასწორია', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    flash('გამოსვლა შესრულდა.', 'info')
    return redirect(url_for('index'))


@app.route('/add', methods=['GET', 'POST'])
def add_news():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("მხოლოდ ადმინებს შეუძლიათ სიახლის დამატება", "danger")
        return redirect(url_for('index'))
    form = NewsForm()
    if form.validate_on_submit():
        news = News(title=form.title.data, content=form.content.data, image_url=form.image_url.data)
        db.session.add(news)
        db.session.commit()
        flash("სიახლე დამატებულია", "success")
        return redirect(url_for('index'))
    return render_template('add_news.html', form=form)


@app.route('/import')
def import_news():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("მხოლოდ ადმინებს შეუძლიათ სიახლეების იმპორტი", "danger")
        return redirect(url_for('index'))

    feed_urls = [
        "https://netgazeti.ge/feed/",
        "https://on.ge/feed",
        "https://www.interpressnews.ge/rss",
        "https://reportiori.ge/rss.xml"
    ]

    def extract_image(entry):
        fallback = url_for('static', filename='images/default.jpg')

        if hasattr(entry, 'media_content'):
            for media in entry.media_content:
                if 'url' in media:
                    return media['url']

        if hasattr(entry, 'media_thumbnail'):
            for thumb in entry.media_thumbnail:
                if 'url' in thumb:
                    return thumb['url']

        if hasattr(entry, 'links'):
            for link in entry.links:
                if 'image' in link.type:
                    return link.href

        if hasattr(entry, 'content'):
            for c in entry.content:
                match = re.search(r'<img[^>]+src="([^">]+)"', c.value)
                if match:
                    return match.group(1)

        return fallback

    count = 0
    for url in feed_urls:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            if News.query.filter_by(title=entry.title).first():
                continue

            image_url = extract_image(entry)

            news = News(
                title=entry.title,
                content=entry.summary if 'summary' in entry else entry.get('description', ''),
                image_url=image_url
            )
            db.session.add(news)
            count += 1

    db.session.commit()
    flash(f"დაემატა {count} სტატია (რეალური ან ფოლბექ სურათით)", "success")
    return redirect(url_for('index'))


# START
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("App running at http://127.0.0.1:5000/")
    app.run(debug=True)
