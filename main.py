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

@app.route("/listadedeseos")
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

@app.route("/login", methods=['POST','GET'])
def login():
	return render_template("login.html")

if __name__ == "__main__":
	app.run(debug = True)