from flask import Flask, redirect, url_for, render_template, request, session
from flask_mysqldb import MySQL
import bcrypt

app = Flask(__name__)
app.secret_key = "Pruebadecontraseñasecretacualquiera"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'dbpos'

#Objeto MySQL
mysql = MySQL(app)

#Encriptamiento
encript = bcrypt.gensalt()

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

@app.route("/registrar-usuario", methods=['POST','GET'])
def registrar():
	if request.method == "GET":
		return render_template("login.html")
	else:
		#Obtención datos
		nombre = request.form['nmNombreRegistro']
		correo = request.form['nmCorreoRegistro']
		contrasena = request.form['nmContrasenaRegistro']
		contrasena_encode = contrasena.encode("utf-8")
		contrasena_encriptada = bcrypt.hashpw(contrasena_encode, encript)

		#Prepara Query para inserción
		sQuery = "INSERT into Login (correo, contrasena, nombre) VALUES (%s, %s, %s)"

		#Cursor para la ejecución
		cur = mysql.connection.cursor()

		#Ejecutar la sentencia
		cur.execute(sQuery, (correo,contrasena_encriptada, nombre))

		#Ejecutar el commit
		mysql.connection.commit()

		#Registrar la sesión
		session['nombre'] = nombre
		#session['correo'] = correo

		#redirigir
		return redirect(url_for('home'))

@app.route("/inicio-de-sesion", methods=['POST','GET'])
def login():
	if request.method == 'GET':
		if 'nombre' in session:
			return redirect(url_for('home'))
		else:
			return render_template("login.html")
	else:
		correo = request.form['nmCorreoLogin']
		cotrasena = request.form['nmContrasenaLogin']
		contrasena_encode = contrasena.encode("utf-8")

		cur = mysql.connection.cursor()

		sQuery = "SELECT correo, contrasena, nombre FROM Login WHERE correo =%s"

		cur.execute(sQuery, [correo])

		usuario = cur.fetchone()

		cur.close()

		if usuario != None:
			contrasena_encriptada_encode = usuario[1].encode()

			print("Password_encode", contrasena_encode)
			print("contrasena_encriptada_encode", contrasena_encriptada_encode)

			if bcrypt.checkpw(contrasena_encode, contrasena_encriptada_encode):
				session['nombre'] = usuario[2]
				session['correo'] = contrasena_encriptada_encode
				return redirect(url_for('home'))
			else:
				flash("La contraseña no es correcta", "alert-warning")
				return render_template("login.html")
		else:
			print("el usuario no existe")
			flash("El correo no existe", "alert-warning")
			return render_template("login.html")

	

if __name__ == "__main__":
	app.run(debug = True)