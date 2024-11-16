from flask import Flask, request, make_response, redirect,url_for, abort
from flask_sqlalchemy import SQLAlchemy
import os, hashlib
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

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
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        digest = kdf.derive(password.encode('utf-8'))
        user = User(name=name, email=email, password=b64encode(salt+digest).decode('ascii'))
        db.session.add(user)
        db.session.commit()
        return make_response(f'<h1> Usuário {user.name} Cadastrado com Sucesso </h1><hr><p><a href="./create">Realizar outro cadastro</a></p>'),201

@app.route('/login',methods=['GET', 'POST'])
def loginPage():
    if request.method=="GET":
        session_cookie = request.cookies.get('session_id')
        res=make_response('<h1>Fazer Login</h1> <hr> <form action="/login" method="POST"><label>Email:</label><input type="text" name="email"><br><label>Senha:</label><input type="password" name="password"><br><button type="submit">Login</button></form>')
        if not session_cookie:
            return res,200
        else:
            sessionData = Session.query.filter_by(id=session_cookie).first()
            #Se usuário tentar voltar na página de login e já estiver logado ele será redirecionado
            if sessionData:
                red = redirect(url_for('homePage'))
                return red, 302
            else:
                return res,200
    elif request.method=="POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first_or_404(description=f'Email não cadastrado')
        user_password=user.password
        saltDigest = b64decode(user_password.encode('ascii'))
        salt = saltDigest[:16]
        digest = saltDigest[16:]
        kdf = Scrypt(salt =salt, length =32, n=2**14, r=8, p=1, backend=default_backend())
        try:
            kdf.verify(password.encode('utf-8'), digest)
            print("Senhas batem!")
        except InvalidKey:
            print("Senhas não batem!")
            return f'<h1>Credenciais não batem</h1><hr><p><a href="./login">Tentar Novamente</a></p>',401
        session_id=b64encode(hashlib.md5(os.urandom(16)).digest()).decode('ascii')
        sessionData=Session(id=session_id,user_id=user.id)
        db.session.add(sessionData)
        db.session.commit()
        page = redirect(url_for('homePage'))
        page.set_cookie('session_id', session_id) 
        return page, 302
           
@app.route('/logout',methods=['GET', 'POST'])
def logoutPage():
    session_cookie = request.cookies.get('session_id')
    sessionData = Session.query.filter_by(id=session_cookie).first()
    if request.method=="POST":
        res = make_response("Logout done")
        db.session.delete(sessionData) 
        db.session.commit()
        return res,200
    else:
        user = User.query.filter_by(id=sessionData.user_id).first()
        res=make_response (f'<h1>Logado como { user.name }</h1><hr><form action="/logout" method="POST"><button type="submit">LogOut</button></form>') 
        return res,200

@app.route('/home')      
def homePage():
    session_cookie = request.cookies.get('session_id')
    if session_cookie:
        sessionData = Session.query.filter_by(id=session_cookie).first()
        if sessionData:
            user = User.query.filter_by(id=sessionData.user_id).first()
            return (f'<h1>Usuário {user.name} logado!</h1><hr><p><a href="./logout">Para fazer logout!</a></p>')
        else:
            abort(401)
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
    
class Session(db.Model):
    id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey(User.id), nullable=False)
