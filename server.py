from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import os
app = Flask(__name__)

@app.route('/')
def indexPage():
    return('<h1> Bem vindo ao servidor! </h1> <hr> <p><a href="./create">Criar usuário</a> </p>')

@app.route('/create', methods=['GET', 'POST'])
def userCreatePage():
    if request.method=="GET":
        return('<h1> Cadastrar Usuário </h1> <hr> <form action="/create" method="POST"><label>Nome:</label><input type="text" name="name"><br><label>Email:</label><input type="text" name="email"><br><label>Senha:</label><input type="password" name="password"><br><button type="submit">Register</button></form>'),200
    elif request.method=="POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return('<h1> Usuário Cadastrado com Sucesso </h1><hr><p><a href="./create">Realizar outro cadastro</a></p>'),201


basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.name