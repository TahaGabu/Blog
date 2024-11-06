from datetime import date
from typing import List

import requests
from requests import request
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, Date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm
from forms import RegisterForm
from forms import LoginForm
from forms import CommentForm
from flask import request

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped[str] = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="parent_post")


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    # blog_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    # posts: Mapped[List["BlogPost"]] = relationship()
    posts = relationship("BlogPost", back_populates="author")
    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    # comments = relationship("Comment", back_populates="comment_author")
    comments = db.relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = db.relationship("BlogPost", back_populates="comments")

# class Comment(db.Model):
#     __tablename__ = "comments"
#     id: Mapped[int] = mapped_column(Integer, primary_key=True)
#     text: Mapped[str] = mapped_column(Text, nullable=False)
#
#     # *******Add child relationship*******#
#     # "users.id" The users refers to the tablename of the Users class.
#     # "comments" refers to the comments property in the User class.
#     author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
#     comment_author = relationship("User", back_populates="comments")


with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app=app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# # made by me
# def admin_only(function):
#     def wrapper_function(**kwargs):
#         if current_user.id == 1:
#             print("Admin")
#             return function(**kwargs)
#         else:
#             print("This is not admin")
#             abort(403)
#     wrapper_function.__name__ = function.__name__
#     return wrapper_function

# now according to the documentation of flask
def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:  
            print("Admin")
            return function(*args, **kwargs)
        else:
            print("This is not admin")
            abort(403)
    return wrapper_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        email = form.data.get("email")
        user_instance = db.session.execute(db.select(User).where(
            User.email == email
        )).scalar()
        if user_instance:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        hash_and_salt_password = generate_password_hash(
            password=form.data.get("password"),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=email,
            password=hash_and_salt_password,
            name=form.data.get("name")
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(user=new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = form.email.data
        password = form.password.data
        user_instance = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user_instance and check_password_hash(pwhash=user_instance.password, password=password):
            login_user(user=user_instance)
            return redirect(url_for('get_all_posts'))
        elif not user_instance:
            flash("The email does not exist, please try again.")
            return redirect(url_for('login'))
        else:
            flash("Incorrect password, please try again.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    print("here")
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    print(posts)
    print("post got")
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    user_authentication = current_user.is_authenticated
    comment_form = CommentForm()
    print(user_authentication)
    if request.method == "POST":
        if user_authentication:
            if comment_form.validate_on_submit():
                comment = Comment(
                    text=comment_form.data.get("comment_text"),
                    author=current_user,
                    parent_post=requested_post
                )
                db.session.add(comment)
                db.session.commit()
        else:
            flash("You need to Login or Register to comment.")
            return redirect(url_for("login"))
    profile_image = requests.post(url="https://gravatar.com/27205e5c51cb03f862138b22bcb5dc20f94a342e744ff6df1b8dc8af3c865109.json")
    return render_template("post.html", post=requested_post, logged_in=user_authentication, user=current_user,
                           form=comment_form, )


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    print("in the function")
    if form.validate_on_submit():
        print("form validated")
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B, %d, %Y")
        )
        print("post instance created")
        db.session.add(new_post)
        db.session.commit()
        print("post has been committed")
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
