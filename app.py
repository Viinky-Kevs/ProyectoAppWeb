from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_socketio import SocketIO
from flask_msearch import Search
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from PIL import Image
import secrets
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
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'productoshorneados.com'
app.config['MAIL_PASSWORD'] = 'productos2022'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MSEARCH_INDEX_NAME'] = 'msearch'
app.config['MSEARCH_PRIMARY_KEY'] = 'id'
app.config['MSEARCH_ENABLE'] = True
#app.config['MSEARCH_LOGGER'] = logging.DEBUG
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

search = Search()
search.init_app(app)

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
	bio_content = database.Column(database.String(1000))
	verified = database.Column(database.Boolean(), default=False)
	commenter = database.relationship('Comment', backref='commenter', lazy='dynamic')
	wish = database.relationship('Wish', backref='liker', lazy='dynamic')

class Comment(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    commented_id = database.Column(database.Integer, database.ForeignKey('products.id'))
    commenter_id = database.Column(database.Integer, database.ForeignKey('user.id'))
    comment_body = database.Column(database.String(200))

class Products(database.Model):
	id = database.Column(database.Integer, primary_key=True)
	productname = database.Column(database.String(30), nullable=False, unique=True)
	price = database.Column(database.Integer, nullable=False)
	quantity = database.Column(database.Integer, nullable=False)
	score = database.Column(database.Integer, nullable=False)
	details = database.Column(database.String(1000))
	image_prod = database.Column(database.String(40), nullable=False, default='pan.jpg')

class Wish(database.Model):
	id = database.Column(database.Integer, primary_key=True)
	product_id = database.Column(database.Integer, database.ForeignKey('products.id'))
	product_id = database.Column(database.Integer, database.ForeignKey('products.price'))
	product_id = database.Column(database.Integer, database.ForeignKey('user.id'))

class Shop(database.Model):
	id = database.Column(database.Integer, primary_key=True)
	product_id = database.Column(database.Integer, database.ForeignKey('products.id'))
	product_id = database.Column(database.Integer, database.ForeignKey('user.id'))
	product_name = database.Column(database.Integer, database.ForeignKey('products.productname'))
	product_price = database.Column(database.Integer, database.ForeignKey('products.price'))
	product_img = database.Column(database.Integer, database.ForeignKey('products.image_prod'))

class RegisterForm(FlaskForm):
	email = StringField("Email",validators=[InputRequired(), Email(message="Email invalido"), 
	Length(max=50)], render_kw={"placeholder": "Email"})
	username = StringField(validators=[InputRequired(), Length(min = 4, max = 20)], 
	render_kw = {"placeholder":"Usuario"})
	password = PasswordField(validators=[InputRequired(), Length(min = 4, max = 20)], 
	render_kw = {"placeholder":"Contraseña"})
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
                raise ValidationError("El nombre de usuario ya existe. Por favor escoge uno diferente.")

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError("Este email ya pertenece a otro usuario. Por favor escoge uno diferente.")


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Email invalido"), Length(max=50)], render_kw={"placeholder": "Email"})
    submit = SubmitField("Enviar correo de nueva contraseña")


class ResetPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message = "Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Nueva contraseña"})


class ChangePasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    current_password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña actual"})
    new_password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Nueva contraseña"})
    submit = SubmitField("Change Password")


class DeleteAccountForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Nombre usuario"})
    password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña"})
    submit = SubmitField("Eliminar mi cuenta")

# Formato comentario
class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Ingesar comentario"})
    submit = SubmitField("Realizar comentario")

# Formato menu

class ProductForm(FlaskForm):
	nameproduct = StringField(validators=[InputRequired(), Length(min=4, max = 20)], 
	render_kw={"placeholder":"Nombre producto"})
	priceproduct = IntegerField(validators=[InputRequired()], render_kw={"placeholder":"Precio producto"})
	quatityproduct = IntegerField(validators=[InputRequired()], render_kw={"placeholder":"Cantidad productos"})
	scoreproduct = IntegerField(validators=[InputRequired()], render_kw={"placeholder":"Puntuación producto"})
	detailsproduct = TextAreaField([Length(min=1, max=1000)], 
	render_kw={"placeholder": "Agregar detalles de plato"})
	imageproduct = FileField(validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
	submitbutton = SubmitField("Publicar producto")

def make_comment():
	form = CommentForm()
	if form.validate_on_submit():
		new_comment = User()


# Foto de perfil del usuario
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

# Foto de plato
def save_image(form_image_product):
    rand_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_image_product.filename)
    picture_name = rand_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images_plates', picture_name)
    form_image_product.save(picture_path)

    output_size = (800, 800)
    i = Image.open(form_profile_pic)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_name

#Definición de rutas
@app.route("/")
def home():
	return render_template("home.html")

@app.route("/lista-de-deseos")
@login_required
def lista():
	return render_template("listadeseos.html")

@app.route("/busqueda", methods=['GET', 'POST'])
def busqueda():
	if request.method == 'POST' and 'tag' in request.form:
		tag = request.form["tag"]
		search = "%{}%".format(tag)
		products = Products.query.filter(Products.productname.like(search))#.paginate(per_page = pages, error_out = True)
		return render_template("buscar.html", products = products, tag = tag)
	return render_template("buscar.html")

@app.route("/ajustes")
def ajustes():
	return render_template("ajustes.html")

@app.route("/carrito-de-compras")
@login_required
def carrito():
	return render_template("carrito.html")

@app.route("/menu")
def menu():
	return render_template("carta.html")

@app.route("/plato")
def plato():
	return render_template("plato.html")

@app.route("/admin-dash")
@login_required
def dashboard():
	if current_user.username == "SuperAdmin":
		length_users = len(User.query.filter().all())
		length_comments = len(Comment.query.filter().all())
		length_products = len(Products.query.filter().all())
		return render_template("dashboard.html", users = length_users,
												comments = length_comments,
												products = length_products)
	else:
		return redirect(url_for('home'))

@app.route("/admin-dash/editar-usuario", methods=['GET','POST'])
@login_required
def lista_usuario():
	if current_user.username == "SuperAdmin":
		pages = 5
		users = User.query.filter().all()
		if request.method == 'POST' and 'tag' in request.form:
			tag = request.form["tag"]
			search = "%{}%".format(tag)
			users = User.query.filter(User.username.like(search))
			return render_template("edituser.html", users = users, tag = tag)

		return render_template("edituser.html", users = users)
	else:
		return redirect(url_for('home'))

@app.route("/admin-dash/agregar-producto", methods=['GET', 'POST'])
@login_required
def agregar_producto():
	if current_user.username == "SuperAdmin":
		product_form = ProductForm()
		if product_form.validate_on_submit():
			if product_form.imageproduct.data:
				image_prod = save_image(product_form.imageproduct.data)
				Products.image_pro = image_prod
				database.session.commit()
			new_product = Products(productname = product_form.nameproduct.data,
			price = product_form.priceproduct.data, quantity = product_form.quatityproduct.data,
			details = product_form.detailsproduct.data, 
			score = product_form.scoreproduct.data)
			database.session.add(new_product)
			database.session.commit()
			return redirect(url_for('dashboard'))
		return render_template("product.html", form = product_form)

	else:
		return redirect(url_for('home'))

@app.route("/admin-dash/lista-productos")
@login_required
def lista_producto():
	if current_user.username == "SuperAdmin":
		products = Products.query.filter().all()
		return render_template("listproducts.html", products = products)
	else:
		return redirect(url_for('home'))

@app.route("/perfil-usuario", methods=['GET', 'POST'])
@login_required
def perfil_usuario():
	if current_user.username == "SuperAdmin":
		return redirect(url_for('dashboard'))
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
		return redirect(url_for('perfil_usuario'))

	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email
		form.bio.data = current_user.bio_content
		profile_pic = url_for('static', filename='profile_pics/' + current_user.profile_pic)
	return render_template("usuario.html", 
							name=current_user.username, 
							email=current_user.email, 
							title="My Profile", 
							form=form,  
							profile_pic=profile_pic)

@app.route("/registrar-usuario", methods=['POST','GET'])
def registrar():
	registerform = RegisterForm()
	if registerform.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(registerform.password.data)
		new_user = User(username=registerform.username.data, password=hashed_password)
		database.session.add(new_user)
		database.session.commit()
		flash("Tu cuenta ha sido creada exitosamente!")
		return redirect(url_for('login'))

	return render_template("signup.html", registerform = registerform)

@app.route("/inicio-de-sesion", methods = ['POST','GET'])
def login():
	loginform = LoginForm()
	if loginform.validate_on_submit():
		user = User.query.filter_by(username = loginform.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, loginform.password.data):
				login_user(user)
				return redirect(url_for('home'))
			if not bcrypt.check_password_hash(user.password, loginform.password.data):
				flash("Contraseña incorrecta.")
		if not user:
			flash("El usuario no existe.")
	if current_user.is_authenticated:
		return redirect('home')
	else:
		return render_template("login.html", loginform = loginform)

@app.route("/cerrar-sesion", methods=['POST','GET'])
@login_required
def cerrar_sesion():
	session.clear()
	logout_user()
	return redirect(url_for('home'))

@app.route("/cambiar-contra", methods=['GET', 'POST'])
@login_required
def cambiar_contrasena():
	change_form = ChangePasswordForm()
	if change_form.validate_on_submit():
		user = User.query.filter_by(email = change_form.email.data).first()
		hashed_password = bcrypt.generate_password_hash(change_form.new_password.data).decode('utf-8')
		if change_form.email.data != current_user.email:
			flash("Email invalido")
			return redirect(url_for('cambiar_contrasena'))
		if not bcrypt.check_password_hash(current_user.password, change_form.current_password.data):
			flash("Contraseña invalida")
			return redirect(url_for('cambiar_contrasena'))
		else:
			current_user.password = hashed_password
			database.session.commit()
			flash('Tu contraeña ha sido actualizada!')
			return redirect(url_for('perfil-usuario'))
	return render_template("cambiarcontra.html", form = change_form, title="Cambiar contraseña")

@app.route("/borrar-cuenta", methods=['GET', 'POST'])
@login_required
def borrar_cuenta():
	delete_form = DeleteAccountForm()
	#comments = Comment.query.filter_by(commenter=current_user).all()
	user = User.query.filter_by(email = delete_form.email.data).first()
	if delete_form.validate_on_submit():
		if delete_form.email.data != current_user.email or delete_form.username.data != current_user.username:
			flash('El email o nombre de usuario no esta asociado con tu cuenta.')
			return redirect(url_for('borrar_cuenta'))
		
		database.session.delete(user)
		database.session.commit()
		flash('Tu cuenta ha sido eliminada', 'Éxito!')
		return redirect(url_for('home'))
	return render_template("borrarcuenta.html", form = delete_form, title = "Borrar mi cuenta")

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('¿Olvidaste tu contraseña?',
                  sender='ksquiroga@uninorte.edu.co',
                  recipients=[user.email])
    msg.body = f'''Para reestablecer tu contraseña, da click en el siguiente link: 
	{url_for('resetear-contra', token=token, _external=True)} 
	Si no solicitaste el reestablecimiento de la contraseña, ignora este mensaje. '''
    mail.send(msg)

@app.route("/olvide-contra", methods = ["GET", "POST"])
def olvide_contra():
	forgot_form = ForgotPasswordForm()
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	if forgot_form.validate_on_submit():
		user = User.query.filter_by(email = forgot_form.email.data).first()
		send_reset_email(user)
		flash("Un email fue enviado a tu correo para reestablecer la contraseña.", 'Éxito!')
	return render_template("olvidecontra.html", form = forgot_form, title="Olvidé contraseña")

@app.route("/resetear-contra/<token>", methods=["GET", "POST"])
def resetear_contra(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('Este es un token invalido', 'warning')
        return redirect(url_for('olvide-contra'))
    reset_form = ResetPasswordForm()
    if reset_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(reset_form.password.data)
        user.password = hashed_password
        database.session.commit()
        flash('Tu contraseña ha sido actualizada!', 'success')
        return redirect(url_for('home'))
    return render_template('resetearcontra.html', title = 'Reset Password', form = reset_form)

if __name__ == "__main__":
	app.run(debug = True)