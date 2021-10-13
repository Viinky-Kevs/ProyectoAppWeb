from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, send, join_room
from flask_sslify import SSLify
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from PIL import Image
import secrets
import hashlib
import os

app = Flask(__name__) 

#Base de datos
database = SQLAlchemy(app)

#Encriptado
bcrypt = Bcrypt(app)

mail = Mail(app)

socketio = SocketIO(app, cors_allowed_origins='*')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
'''
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_BLOGGY")
app.config['MAIL_PASSWORD'] = os.environ.get("PASSWORD_BLOGGY")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
'''

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

@app.before_request
def make_session_permanent():
    session.permanent = True


class User(database.Model, UserMixin):
	id = database.Column(database.Integer, primary_key=True)
	email = database.Column(database.String(30), unique=True)
	username = database.Column(database.String(20), nullable=False, unique=True)
	password = database.Column(database.String(80), nullable=False)
	profile_pic = database.Column(database.String(40), nullable=False, default='default.jpg')
	#commenter = database.relationship('Comment', backref='commenter', lazy='dynamic')
	#wish = database.relationship('Wish', backref='liker', lazy='dynamic')
	bio_content = database.Column(database.String(1000))
	verified = database.Column(database.Boolean(), default=False)

'''
class Comment(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    commented_id = database.Column(database.Integer, database.ForeignKey('post.id'))
    commenter_id = database.Column(database.Integer, database.ForeignKey('user.id'))
    comment_body = database.Column(database.String(100))
'''

#Administrador
class AdminModelView(ModelView):
    def is_accessible(self):
        if 'logged_in' in session:
            return True
        else:
            abort(403)

admin = Admin(app, name='Admin-restaurante', template_mode='bootstrap4')
admin.add_view(AdminModelView(User, database.session))
#admin.add_view(AdminModelView(Comment, database.session))

class RegisterForm(FlaskForm):
	email = StringField("Email",validators=[InputRequired(), Email(message="Email invalido"), Length(max=50)], render_kw={"placeholder": "Email"})
	username = StringField(validators=[InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder":"Usuario"})
	password = PasswordField(validators=[InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder":"Contraseña"})
	submit = SubmitField("Registrar")

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			raise ValidationError("El usuario ya existe. Por favor escoge un nombre de usuario diferente")

	def validate_email(self, email):
		existing_user_email = User.query.filter_by(email=email.data).first()
		if existing_user_email:
			raise ValidationError("El email ya pertenece a otro usuario. Por favor introduce uno diferente.")


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Usuario"})
	password = PasswordField("Password", validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña"})
	submit = SubmitField("Iniciar Sesión")

	def validate_username(self, username):
		username = User.query.filter_by(username=username.data).first()
		if not username:
			raise ValidationError('El usuario no existe.')

class BioForm(FlaskForm):
    bio = TextAreaField('Bio', [Length(min=0, max=1000)])
    submit = SubmitField("Actualizar información")

class UpdateAccount(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Editar email"})
    username = StringField("Username", validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Editar nombre de usuario"})
    bio = TextAreaField([Length(min=0, max=1000)], render_kw={
        "placeholder": "Editar información"})
    profile_pic = FileField(validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Actualizar cuenta')

    def validate_username(self, username):
        if current_user.username != username.data:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    "That username already exists. Please choose a different one.")

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError(
                    "That email address belongs to different user. Please choose a different one.")


class ForgotPasswordForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Email(
        message="Email invalido"), Length(max=50)], render_kw={"placeholder": "Email"})
    submit = SubmitField("Enviar correo de nueva contraseña")


class ResetPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})


class ChangePasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    current_password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Current Password"})
    new_password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "New Password (4 minimum)"})
    submit = SubmitField("Change Password")


class DeleteAccountForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Delete My Account")


class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Enter Comment"})
    submit = SubmitField("Add Comment")


class UserSearchForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Search For Users"})


class MessageForm(FlaskForm):
    message = StringField(validators=[InputRequired(), Length(
        min=4, max=200)], render_kw={"placeholder": "Send A Message"})


def save_picture(form_profile_pic):
    rand_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_profile_pic.filename)
    picture_name = rand_hex + f_ext
    picture_path = os.path.join(
        app.root_path, 'static/profile_pics', picture_name)
    form_profile_pic.save(picture_path)

    output_size = (125, 125)
    i = Image.open(form_profile_pic)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_name

#Definición de rutas
@app.route("/")
def home():
	return render_template("home.html")

@login_required
@app.route("/lista-de-deseos")
def lista():
	return render_template("listadeseos.html")

@app.route("/busqueda")
def busqueda():
	return render_template("buscar.html")

@app.route("/ajustes")
def ajustes():
	return render_template("ajustes.html")

@login_required
@app.route("/carrito-de-compras")
def carrito():
	return render_template("carrito.html")

@app.route("/menu")
def menu():
	return render_template("carta.html")

@app.route("/plato")
def plato():
	return render_template("plato.html")

@login_required
@app.route("/admin-dash")
def dashboard():
	return render_template("dashboard.html")

@login_required
@app.route("/perfil-usuario")
def perfil_usuario():
	form = UpdateAccount()
	if form.validate_on_submit():
		if form.profile_pic.data:
			picture_file = save_picture(form.profile_pic.data)
			current_user.profile_pic = picture_file
		
		current_user.username = form.username.data
		current_user.email = form.email.data
		current_user.bio_content = form.bio.data
		database.session.commit()
		flash('Tu cuenta ha sido actualizada!', 'Exito!')
		return redirect(url_for('perfil-usuario'))

	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email
		form.bio.data = current_user.bio_content
		profile_pic = url_for('static', filename='profile_pics/' + current_user.profile_pic)
	return render_template("usuario.html", name=current_user.username, email=current_user.email, title="My Profile", form=form,  profile_pic=profile_pic)

@app.route("/registrar-usuario", methods=['POST','GET'])
def registrar():
	registerform = RegisterForm()
	if registerform.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(registerform.password.data)
		new_user = User(username=registerform.username.data, password=hashed_password)
		database.session.add(new_user)
		database.session.commit()
		flash("Tu cuenta ha sido creada exitosamente!")
		return redirect(url_for('inicio-de-sesion'))

	return render_template("signup.html", registerform = registerform)

@app.route("/inicio-de-sesion", methods = ['POST','GET'])
def login():
	loginform = LoginForm()
	if loginform.validate_on_submit():
		user = User.query.filter_by(username = loginform.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, loginform.password.data):
				login_user(user)
				return redirect(url_for('inicio-de-sesion'))
			if not bcrypt.check_password_hash(user.password, loginform.password.data):
				flash("Contraseña incorrecta.")
		if not user:
			flash("El usuario no existe.")
	if current_user.is_authenticated:
		return redirect('/')
	else:
		return render_template("login.html", loginform = loginform)

@app.route("/cerrar-sesion", methods=['POST','GET'])
@login_required
def cerrar_sesion():
	logout_user()
	return redirect(url_for('home'))

@app.route("/cambiar-contra", methods=['GET', 'POST'])
@login_required
def cambiar_contrasena():
	change_form = ChangePasswordForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
		if form.email.data != current_user.email:
			flash("Email invalido")
			return redirect(url_for('cambiar_contrasena'))
		if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
			flash("Contraseña invalida")
			return redirect(url_for('cambiar_contrasena'))
		else:
			current_user.password = hashed_password
			database.session.commit()
			flash('Tu contraeña ha sido actualizada!')
			return redirect(url_for('perfil-usuario'))
	return render_template("cambiarcontra.html", change_form = change_form, title="Cambiar contraseña")

@app.route("/borrar-cuenta", methods=['GET', 'POST'])
@login_required
def borrar_cuenta():
	delete_form = DeleteAccountForm()
	posts = current_user.posts
	sent_messages = Message.query.filter_by(sender=current_user).all()
	received_messages = Message.query.filter_by(receiver=current_user).all()
	comments = Comment.query.filter_by(commenter=current_user).all()
	user = User.query.filter_by(email=form.email.data).first()
	if form.validate_on_submit():
		if form.email.data != current_user.email or form.username.data != current_user.username:
			flash('El email o nombre de usuario no esta asociado con tu cuenta.')
			return redirect(url_for('borrar_cuenta'))
		for post in posts:
			database.session.delete(post)
		for message in sent_messages:
			database.session.delete(message)
		for message in received_messages:
			database.session.delete(message)
		for comment in comments:
			database.session.delete(comment)
		
		database.session.delete(user)
		database.session.commit()
		flash('Tu cuenta ha sido eliminada', 'Éxito!')
		return redirect(url_for('home'))
	return render_template("borrar_cuenta.html", form=form, title="Borrar mi cuenta")

@app.route("/olvide-contra", methods=["GET", "POST"])
def olvide_contra():
	forgot_form = ForgotPasswordForm()
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		send_reset_email(user)
		flash("Un email fue enviado a tu correo para reestablecer la contraseña.", 'Éxito!')
	return render_template("olvide_contra.html", forgot_form = forgot_form, title="Olvidé contraseña")

if __name__ == "__main__":
	app.run(debug = True)