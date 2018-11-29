import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, make_response, send_file
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm, DecryptForm
from flaskblog.models import User, Post, Hmac, Replay
from flask_login import login_user, current_user, logout_user, login_required
import binascii
# import rsa
import crypto
import sys, json
sys.modules['Crypto'] = crypto
# from Crypto.Cipher import AES
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from base64 import b64decode
import hashlib
import hmac, random
import base64

@app.route("/")
@app.route("/home")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('home.html', posts=posts, shuffle_string = lambda x: ''.join(random.sample(str(x),len(str(x)))))


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    replay_token = generate_iv()
    if request.method == 'POST':
        data = request.data
        data = json.loads(data.decode("utf-8"))
        signature = check_hmac(data['title']+data['content'], data['hmac'])

        if str(data["hash"]) != str(signature.decode('utf-8')): 
            flash('Man in the middle detected', 'warning')
            return redirect(url_for('login'))
            # return 'Man in the middle detected'

        res = Replay.query.filter_by(text=replay_token).all()

        if res and res.used == 1:
            flash('Replay attack tried', 'warning')
            return redirect(url_for('login'))

        data['content'] = data['content'].strip()
        data['title'] = data['title'].strip()

        title = hash_sha256(data['title'])

        res = Hmac.query.filter_by(title=title).all()
        if res:
            return '1'

        content = hash_sha256(data['content'])
        res = Hmac.query.filter_by(content=content).all()
        if res:
            return '2'

        try: 
            iv = generate_iv()
            post = Post(title=data['title_encrypted'], content=data['content_encrypted'], author=current_user, title_unencrypted=data['title'], content_unencrypted=data['content'])
            db.session.add(post)
            db.session.commit()

            hmac = Hmac(title=title, content=content, author=post)
            db.session.add(hmac)
            db.session.commit()

            replay = Replay.query.get(5)
            replay.used = 1
            db.session.commit()


            # text = 'key: ' + key +'\niv: ' + iv + '\nurl is: ' + 'post/' + str(post.id)
            text = 'key: ' 
        except Exception as e:
            return str('Error occured!')

        return text

    hmac = Replay(text=replay_token, used=0)
    db.session.add(hmac)
    db.session.commit()
    return render_template('create_post.html', title='New Post',
                           form=form, legend='New Post', replay_token=replay_token)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def post(post_id):
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    post = Post.query.get_or_404(post_id)
    form = DecryptForm()
    iamowner = False
    # if pppp == 1: iamowner=True
    if request.method == 'POST':
        return render_template('post.html', title=post.title, post=post, form=form, iamowner=True, legend='Provide me the secret to get the secret message!')

    elif request.method == 'GET':
        return render_template('post.html', title=post.title, post=post, form=form, iamowner=iamowner, legend='Provide me the secret to get the secret message!')



# @app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
# @login_required
# def update_post(post_id):
#     post = Post.query.get_or_404(post_id)
#     if post.author != current_user:
#         abort(403)
#     form = PostForm()
#     if form.validate_on_submit():
#         post.title = form.title.data
#         post.content = form.content.data
#         db.session.commit()
#         flash('Your post has been updated!', 'success')
#         return redirect(url_for('post', post_id=post.id))
#     elif request.method == 'GET':
#         form.title.data = post.title
#         form.content.data = post.content
#     return render_template('create_post.html', title='Update Post',
#                            form=form, legend='Update Post')


@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):

    hmac = Hmac.query.filter_by(post_id=post_id).first_or_404()
    db.session.delete(hmac)
    db.session.commit()

    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()

    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)


@app.route("/generate/key", methods=['GET', 'POST'])
def generate_key():
    return secrets.token_hex(16)

def generate_iv():
    return secrets.token_hex(8)

def download_file(text, filename):
    csv = text
    response = make_response(csv)
    cd = 'attachment; filename='+filename
    response.headers['Content-Disposition'] = cd 
    response.mimetype='text/csv'
    return response

def encrypt(key, iv, data):
    encryption_suite = AES.new(key, AES.MODE_CFB, iv)
    return encryption_suite.encrypt(data)

def decrypt(key, iv, cipher_text):
    decryption_suite = AES.new(key, AES.MODE_CFB, iv)
    return decryption_suite.decrypt(cipher_text)

def generate_rsa_keys():
    # (pubkey, privkey) = rsa.newkeys(1024)
    # print(pubkey)
    # file_path = os.path.join(app.root_path, 'static/profile_pics', str(current_user.id)+'.pem')
    # with open(file_path, mode='wb') as privatefile:
    #     privatefile.write(privkey)

    # return (pubkey, privkey)
    new_key = RSA.generate(2048, e=65537)

    #The private key in PEM format
    private_key = new_key.exportKey("PEM")

    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")

    # print private_key
    file_path = os.path.join(app.root_path, 'static/profile_pics', 'private_key.pem')
    fd = open(file_path, "wb")
    fd.write(private_key)
    fd.close()

    # print public_key
    file_path = os.path.join(app.root_path, 'static/profile_pics', 'public_key.pem')
    fd = open(file_path, "wb")
    fd.write(public_key)
    fd.close()

def check_hmac(message, key):
    message = message.encode('utf-8')
    secret = key.encode('utf-8')
    signature = base64.b64encode(hmac.new(secret, message, digestmod=hashlib.sha256).digest())
    return  signature

def hash_sha256(hash_string):
    sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

