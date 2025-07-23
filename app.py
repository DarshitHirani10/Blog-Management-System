from flask import Flask, render_template, request, url_for, redirect, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
import random
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from PIL import Image
import io


def is_allowed_image(file_storage):
    # Check if uploaded file is a valid image using Pillow
    if not file_storage or not file_storage.filename:
        return False
    allowed_ext = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
    ext = file_storage.filename.rsplit('.', 1)[-1].lower()
    if ext not in allowed_ext:
        return False
    file_bytes = file_storage.read()
    file_storage.seek(0)
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify()
        return True
    except Exception:
        return False                        


# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blogify.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
load_dotenv()
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"] = os.environ.get("MAIL_PORT")
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS")


# # Initialize Flask-Mail
mail = Mail(app)


# # # Initialize database
db = SQLAlchemy(app)


# # # Create uploads folder if it doesn't exist
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])


# # Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    bio = db.Column(db.Text, default='')
    profile_pic = db.Column(db.String(300), default='default.png')
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='commenter', lazy=True)
    likes = db.relationship('Like', backref='liker', lazy=True)
    followers = db.relationship('Follow', foreign_keys='Follow.following_id', backref='following', lazy='dynamic')
    following = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic')


# # Define Blog model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
    likes = db.relationship('Like', backref='post', lazy=True, cascade="all, delete-orphan")


# # Define Comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


# # Define Like model
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


# # Define Follow model
class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# Create database
with app.app_context():
    db.create_all()


# # Home route
@app.route('/')
@app.route('/welcome')
def welcome():
    username = session.get('username')
    user_id = session.get('user_id')
    user = None
    if username:
        user = User.query.filter_by(username=username).first()
        if user:
            posts = Post.query.filter(Post.user_id != user.id).order_by(Post.created_at.desc()).all()
        else:
            posts = Post.query.order_by(Post.created_at.desc()).all()
    else:
        posts = Post.query.order_by(Post.created_at.desc()).all()
    posts_data = []
    for post in posts:
        likes = Like.query.filter_by(post_id=post.id).count()
        comments_count = Comment.query.filter_by(post_id=post.id).count()
        user_liked = False
        is_following_author = False
        if user_id:
            user_liked = Like.query.filter_by(post_id=post.id, user_id=user_id).first() is not None
            if user_id != post.author.id:
                is_following_author = Follow.query.filter_by(follower_id=user_id, following_id=post.author.id).first() is not None
        posts_data.append({
            'post': post,
            'likes': likes,
            'comments_count': comments_count,
            'user_liked': user_liked,
            'is_following_author': is_following_author
        })
    return render_template('welcome.html', username=username, posts_data=posts_data)


# # Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    form_data = {}
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        bio = request.form.get('bio', '')
        # Don't keep password fields for security
        form_data = {
            'username': username,
            'email': email,
            'bio': bio
        }
        profile_pic_file = request.files.get('profile_pic')
        # Check if username or email is already used
        if User.query.filter_by(username=username).first():
            msg = 'Username already exists.'
            return render_template('register.html', msg=msg, form_data=form_data)
        if User.query.filter_by(email=email).first():
            msg = 'Email already exists.'
            return render_template('register.html', msg=msg, form_data=form_data)
        if password != confirm_password:
            msg = 'Passwords do not match.'
            return render_template('register.html', msg=msg, form_data=form_data)
       # Handle profile picture upload
        profile_pic_path = 'default.png'
        if profile_pic_file and profile_pic_file.filename:
            if is_allowed_image(profile_pic_file):
                filename = secure_filename(profile_pic_file.filename)
                profile_pic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic_path = f'uploads/{filename}'
            else:
                msg = 'Only image files are allowed for profile picture.'
                return render_template('register.html', msg=msg, form_data=form_data)
        else:
            profile_pic_path = 'default.png'
        # Generate a random 6-digit OTP
        otp = str(random.randint(100000, 999999))
        # Store temp user data and OTP in session
        session['temp_user'] = {
            'username': username,
            'email': email,
            'password': password,
            'bio': bio,
            'profile_pic': profile_pic_path
        }
        session['otp'] = otp
        # Send the OTP email
        try:
            otp_msg = Message(
                subject='OTP Verification - Blogify',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email],
                body=f"Hi {username},\n\nYour OTP for registration is: {otp}\n\nPlease enter this to complete registration."
            )
            mail.send(otp_msg)
            return redirect(url_for('verify_otp'))
        except Exception as e:
            msg = 'Failed to send OTP. Please try again later.'
            print("Email error:", e)
            return render_template('register.html', msg=msg)
    return render_template('register.html', msg=msg)


# # OTP verification route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    msg = ''
    temp_user = session.get('temp_user')
    # No temp user in session? Redirect to register
    if not temp_user:
        return redirect(url_for('register'))
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        actual_otp = session.get('otp')
        if entered_otp == actual_otp:
            # Create and save the user
            hashed_password = generate_password_hash(temp_user['password'])
            new_user = User(
                username=temp_user['username'],
                email=temp_user['email'],
                password=hashed_password,
                bio=temp_user.get('bio', ''),
                profile_pic=temp_user.get('profile_pic', 'default.png')
            )
            db.session.add(new_user)
            db.session.commit()
            # Clear session
            session.pop('temp_user', None)
            session.pop('otp', None)
            msg = 'Registration successful. Please log in.'
            return render_template('welcome.html', msg=msg, username=temp_user['username'])
        else:
            msg = 'Invalid OTP. Please try again.'
    return render_template('verify_otp.html', msg=msg)


# # Forgot password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    msg = ''
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_email'] = email
            session['reset_otp'] = otp
            try:
                msg_body = f"Hi {user.username},\n\nYour OTP for password reset is: {otp}"
                otp_msg = Message(subject='Password Reset OTP - Blogify',
                                  sender=app.config['MAIL_USERNAME'],
                                  recipients=[email],
                                  body=msg_body)
                mail.send(otp_msg)
                return redirect(url_for('verify_reset_otp'))
            except Exception as e:
                print("Email error:", e)
                msg = 'Failed to send OTP. Try again later.'
        else:
            msg = 'Email not registered.'
    return render_template('forgot_password.html', msg=msg)


# # OTP verification for password reset
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    msg = ''
    if not session.get('reset_email'):
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        actual_otp = session.get('reset_otp')
        if entered_otp == actual_otp:
            return redirect(url_for('reset_password'))
        else:
            msg = 'Invalid OTP. Try again.'
    return render_template('verify_reset_otp.html', msg=msg)


# # Reset password route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    msg = ''
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']
        if password != confirm:
            msg = 'Passwords do not match.'
            return render_template('reset_password.html', msg=msg)
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            # Clean up session
            session.pop('reset_email', None)
            session.pop('reset_otp', None)
            msg = 'Password reset successful. Please log in.'
            return render_template('login.html', msg=msg)
        else:
            msg = 'User not found.'
    return render_template('reset_password.html', msg=msg)


# login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    # Check if a user is already logged in
    if 'username' in session:
        return render_template('welcome.html', msg=msg, username=session['username'])
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            session['user_id'] = user.id  # Store user ID in session
            return redirect(url_for('welcome'))  # Redirect to welcome page
        else:
            msg = 'Invalid username or password.'
            return render_template('login.html', msg=msg)
    return render_template('login.html', msg=msg)


# # Logout route
@app.route("/logout")
def logout():
    if 'username' in session:
        session.pop('username', None)  # Clear the session
        session.pop('user_id', None)  # Clear the user ID from session
        msg = 'You have been logged out.'
    else:
        msg = 'You are not logged in.'
        return redirect(url_for('welcome' , msg=msg))  # Redirect to welcome page if not logged in
    return render_template('welcome.html', msg=msg, username=None)


# # Create post route
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    msg = ''
    if 'username' not in session:
        msg = 'You need to log in to create a post.'
        return render_template('login.html', msg=msg)
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image_file = request.files.get('image')
        image_url = request.form.get('image_url')
        image_path = None
        if image_file and image_file.filename:
            if is_allowed_image(image_file):
                filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = f'uploads/{filename}'
            else:
                msg = 'Only image files are allowed for post images.'
                return render_template('create_post.html', msg=msg)
        elif image_url and image_url.startswith(('http://', 'https://')):
            image_path = image_url
        user = User.query.filter_by(username=session['username']).first()
        new_post = Post(title=title, content=content, image=image_path, author=user)
        db.session.add(new_post)
        db.session.commit()
        msg = 'Post created successfully!'
        return render_template('welcome.html', msg=msg, username=session['username'])
    return render_template('create_post.html', msg=msg)


# # Edit post route
@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    msg = ''
    post = Post.query.get_or_404(post_id)
    if 'user_id' not in session or post.user_id != session['user_id']:
        abort(403)
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        image_file = request.files.get('image')
        image_url = request.form.get('image_url')
        if image_file and image_file.filename:
            if is_allowed_image(image_file):
                filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                post.image = f'uploads/{filename}'
            else:
                msg = 'Only image files are allowed for post images.'
                return render_template('edit_post.html', post=post, msg=msg)
        elif image_url and image_url.startswith(('http://', 'https://')):
            post.image = image_url
        db.session.commit()
        msg = 'Post updated successfully!'
        return redirect(url_for('view_post', post_id=post.id))
    return render_template('edit_post.html', post=post, msg=msg)


# # Delete post route
@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Only the post owner can delete
    if 'user_id' not in session or post.user_id != session['user_id']:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('view_profile', user_id=session['user_id']))


# # Comment on post route
@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    msg = ''
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        content = request.form['content']
        # Check if the user is logged in
        if 'username' not in session:
            msg = 'You need to log in to comment.'
            return render_template('login.html', msg=msg)
        # Create and save the comment
        user = User.query.filter_by(username=session['username']).first()
        new_comment = Comment(content=content, post=post, commenter=user)
        db.session.add(new_comment)
        db.session.commit()
        msg = 'Comment added successfully!'
        return redirect(url_for('view_post', post_id=post.id))
    

# # Like post route
@app.route('/like/<int:post_id>', methods=['POST'])
def like(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    existing = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    if not existing:
        like = Like(user_id=user_id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
    # No message, just redirect back
    return redirect(request.referrer or url_for('view_post', post_id=post_id))


# # Unlike post route
@app.route('/unlike/<int:post_id>', methods=['POST'])
def unlike(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
    # No message, just redirect back
    return redirect(request.referrer or url_for('view_post', post_id=post_id))


# # Follow user route
@app.route('/follow/<int:user_id>', methods=['POST'])
def follow(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    follower_id = session['user_id']
    if follower_id != user_id:
        existing = Follow.query.filter_by(follower_id=follower_id, following_id=user_id).first()
        if not existing:
            follow = Follow(follower_id=follower_id, following_id=user_id)
            db.session.add(follow)
            db.session.commit()
    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('welcome'))


# # Unfollow user route
@app.route('/unfollow/<int:user_id>', methods=['POST'])
def unfollow(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    follower_id = session['user_id']
    follow = Follow.query.filter_by(follower_id=follower_id, following_id=user_id).first()
    if follow:
        db.session.delete(follow)
        db.session.commit()
    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('welcome'))


# # Profile route
@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user.id).all()
    followers = Follow.query.filter_by(following_id=user.id).count()
    following = Follow.query.filter_by(follower_id=user.id).count()
    is_own_profile = session.get('user_id') == user.id
    if 'user_id' in session and not is_own_profile:
        is_following = Follow.query.filter_by(follower_id=session['user_id'], following_id=user.id).first() is not None
    else:
        is_following = False
    return render_template(
        'profile.html',
        user=user,
        posts=posts,
        followers=followers,
        following=following,
        is_following=is_following,
        is_own_profile=is_own_profile
    )


# # Edit profile route
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    msg = ''
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if request.method == 'POST':
        user.bio = request.form['bio']
        profile_pic_file = request.files.get('profile_pic')
        profile_pic_url = request.form.get('profile_pic_url')
        if profile_pic_file and profile_pic_file.filename:
            if is_allowed_image(profile_pic_file):
                filename = secure_filename(profile_pic_file.filename)
                profile_pic_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_pic = f'uploads/{filename}'
            else:
                msg = 'Only image files are allowed for profile picture.'
                return render_template('edit_profile.html', user=user, msg=msg)
        elif profile_pic_url and urlparse(profile_pic_url).scheme in ['http', 'https']:
            user.profile_pic = profile_pic_url
        db.session.commit()
        msg = 'Profile updated successfully!'
        return redirect(url_for('view_profile', user_id=user.id))
    return render_template('edit_profile.html', user=user, msg=msg)


# # Post route
@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post.id).all()
    likes = Like.query.filter_by(post_id=post.id).count()
    # Check if the logged-in user is following the post's author
    if 'username' in session:
        logged_in_user = User.query.filter_by(username=session['username']).first()
        is_following = Follow.query.filter_by(follower_id=logged_in_user.id, following_id=post.user_id).first() is not None
    else:
        is_following = False
    return render_template('post.html', post=post, comments=comments, likes=likes, is_following=is_following)


# Delete comment route
@app.route('/delete_comment/<int:comment_id>/<int:post_id>', methods=['POST'])
def delete_comment(comment_id, post_id):
    if 'user_id' not in session:
        abort(403)
    comment = Comment.query.get_or_404(comment_id)
    # Only allow the comment's owner to delete
    if comment.user_id != session['user_id']:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('view_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)