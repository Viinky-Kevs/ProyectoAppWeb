from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
#app.secret_key = "Pruebadecontraseñasecretacualquiera"

#Base de datos
database = SQLAlchemy(app)

#Encriptado
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class User(database.Model, UserMixin):
	id = database.Column(database.Integer, primary_key=True)
	username = database.Column(database.String(20), nullable=False, unique=True)
	password = database.Column(database.String(80), nullable=False)

class RegisterForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder":"Usuario"})
	password = PasswordField(validators=[InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder":"Contraseña"})
	submit = SubmitField("Registrar")

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			raise ValidationError("That username already exists. Please choose a different one.")

	def validate_email(self, email):
		existing_user_email = User.query.filter_by(email=email.data).first()
		if existing_user_email:
			raise ValidationError("That email address belongs to different user. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Usuario"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña"})
    submit = SubmitField("Iniciar Sesión")

    def validate_username(self, username):
        username = User.query.filter_by(username=username.data).first()
        if not username:
            raise ValidationError('Account does not exists.')

#Definición de rutas
@app.route("/")
def home():
	return render_template("index.html")

@app.route("/lista-de-deseos")
def lista():
	return render_template("listadeseos.html")

@app.route("/ajustes")
def ajustes():
	return render_template("ajustes.html")

@app.route("/carrito-de-compras")
def carrito():
	return render_template("carrito.html")

@app.route("/menu")
def menu():
	return render_template("carta.html")

@app.route("/plato")
def plato():
	return render_template("plato.html")

@app.route("/admin-dash")
def dashboard():
	return render_template("dashboard.html")

@app.route("/registrar-usuario", methods=['POST','GET'])
def registrar():
	form = RegisterForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, password=hashed_password)
		database.session.add(new_user)
		database.session.commit()
		return redirect(url_for('login'))

	return render_template("signup.html", form = form)

@app.route("/inicio-de-sesion", methods=['POST','GET'])
def login():
	loginform = LoginForm()
	if loginform.validate_on_submit():
		user = User.query.filter_by(username=loginform.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, loginform.password.data):
				login_user(user)
				return redirect(url_for("home"))
	return render_template("login.html", form = loginform)

@app.route("/cerrar-sesion", methods=['POST','GET'])
@login_required
def cerrar_sesion():
	logout_user()
	return redirect(url_for('home'))


if __name__ == "__main__":
	app.run(debug = True)