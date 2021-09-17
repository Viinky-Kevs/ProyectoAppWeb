from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)

@app.route("/")
def home():
	return render_template("index.html")

@app.route("/listadedeseos")
def lista():
	return render_template("listadeseos.html")

if __name__ == "__main__":
	app.run(debug = True)