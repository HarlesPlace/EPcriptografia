from flask import Flask, request, make_response, redirect,url_for, abort
from flask_sqlalchemy import SQLAlchemy
import os
app = Flask(__name__)

@app.route('/')
def indexPage():
    return('<h1> Bem vindo ao servidor! </h1> <hr> <p><a href="./create">Criar usuário</a> </p><br><p><a href="./login">Fazer Login</a></p> <br> <p><a href="./home">Página Principal</a> </p>')

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
        return make_response(f'<h1> Usuário {user.name} Cadastrado com Sucesso </h1><hr><p><a href="./create">Realizar outro cadastro</a></p>'),201

@app.route('/login',methods=['GET', 'POST'])
def loginPage():
    user_cookie = request.cookies.get('user_id')
    if request.method=="GET":
        if not user_cookie:
            return('<h1>Fazer Login</h1> <hr> <form action="/login" method="POST"><label>Email:</label><input type="text" name="email"><br><label>Senha:</label><input type="password" name="password"><br><button type="submit">Login</button></form>'),200
        else:
            #Se usuário tentar voltar na página de login e já estiver logado ele será redirecionado
            red = redirect(url_for('homePage'))
            return red, 302
    elif request.method=="POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first_or_404(description=f'Email não cadastrado')
        user_password=user.password
        if password==user_password:
            user_id = redirect(url_for('homePage'))
            user_id.set_cookie('user_id', str(user.id)) 
            return user_id, 302
        else:
            return f'<h1>Credenciais não batem</h1><hr><p><a href="./login">Tentar Novamente</a></p>',401
           
@app.route('/logout',methods=['GET', 'POST'])
def logoutPage():
    if request.method=="POST":
        res = make_response("Logout done")
        res.set_cookie('user_id', 'identificação expirada', max_age=0)
        return res,200
    else:
        user_cookie = request.cookies.get('user_id')
        user = User.query.filter_by(id=user_cookie).first()
        k=make_response (f'<h1>Logado como { user.name }</h1><hr><form action="/logout" method="POST"><button type="submit">LogOut</button></form>') 
        return k,200

@app.route('/home')      
def homePage():
    user_cookie = request.cookies.get('user_id')
    if user_cookie:
        user = User.query.filter_by(id=user_cookie).first()
        return (f'<h1>Usuário {user.name} logado!</h1><hr><p><a href="./logout">Para fazer logout!</a></p>')
    else:
        abort(401)

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