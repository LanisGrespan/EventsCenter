import click
from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask.cli import with_appcontext
from connection import db
from model import User
from flask_login import LoginManager, login_user , logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

# Configuração do aplicativo Flask
app = Flask(__name__)
app.secret_key = "abax"

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'  # Define a rota de login para redirecionar não autenticados
login_manager.init_app(app)

# Configuração do Flask-Bcrypt
bcrypt = Bcrypt(app)

# Configure o URI do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///flaskola.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def init_db():
    db.drop_all()
    db.reflect() # Pega as tabelas criadas no model e joga no database

# Comando para inicializar o banco de dados
@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear existing data and create new tables."""

    init_db()
    click.echo("Initialized the database.")

app.cli.add_command(init_db_command)

# Configuração do login_manager para redirecionar para a página de login
login_manager.login_view = 'login'

# Carregando o usuário com base no ID
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Definição das rotas
@app.route("/")
def index():
    if 'username' in session:
        return render_template("index.html")  # Página principal
    else:
        return redirect(url_for('login'))  # Redireciona para a página de login


#isso quebrou o codigo
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False  # Verificar se o checkbox foi marcado

        # Verificar as credenciais
        user = User.query.filter_by(username=username, password=password).first()

        # if user and bcrypt.check_password_hash(user.password, password):
        #     login_user(user)
        #     return redirect(url_for('index'))
        # else:
        #     # Credenciais incorretas, exibe mensagem de erro
        #     flash('Nome de usuário ou senha incorretos')
        #     return redirect(url_for('login'))

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember)  # Usar a flag 'remember' para manter o login
            
            # Se o checkbox "lembrar de mim" foi marcado, setar a sessão para o tempo desejado
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)  # O usuário será lembrado por 30 dias
            return redirect(url_for('index'))  # Após login bem-sucedido, redireciona para a home
        else:
            flash('Credenciais incorretas. Tente novamente.', 'error')
            return render_template('login.html')

    return render_template('login.html')

# Página de logout (com @login_required, agora só acessível por usuários logados)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/compra", methods=('GET', 'POST'))
@login_required
def compra():
    
    erros = []
    message = ""

    if request.method=="POST":
        nome = request.form.get("nome")
        telefone = request.form.get("telefone")
        email = request.form.get("email")
        cpf = request.form.get("cpf")
        idade = request.form.get("idade")
        evento = request.form.get("evento")
        valor = request.form.get("valor")

        # Validações 
        if not nome: erros.append("Nome é um campo obrigatório")
        if not email: erros.append("Email é um campo obrigatório")

        if len(erros) == 0:
            #altera usuário no banco de dados
            from model import Inscricao
            inscricao = Inscricao(**{"nome": nome, "email": email, "cpf": cpf, "idade": idade, "evento": evento, "valor": valor, "telefone": telefone, })
            db.session.add(inscricao)
            db.session.commit() # persiste no banco

            message = "Sua reserva for feita com sucesso! Realize o pagamento no local."

    return render_template("compra.html", message=message)

@app.route("/contato", methods=("POST",)) 
def contato():
    import json
    from model import Contato
    erros = []

    # if request.method=="POST":
    nome = request.form.get("nome")
    email = request.form.get("email")
    assunto = request.form.get("assunto")
    mensagem = request.form.get("mensagem")

    # Validações 
    if not nome: erros.append("Nome é um campo obrigatório")
    if not email: erros.append("Email é um campo obrigatório")
    if not assunto: erros.append("Assunto é um campo obrigatório")
    if not mensagem: erros.append("Mensagem é um campo obrigatório")
    
    if len(erros) == 0:
        #altera usuário no banco de dados
        contato = Contato(**{"nome": nome, "email": email, "assunto": assunto, "mensagem": mensagem})
        # Outra forma
        # contato = Contato()
        # contato.nome = nome
        # contato.email = email
        # contato.assunto = assunto
        # contato.mensagem = mensagem

        db.session.add(contato)
        db.session.commit() # persiste no banco

        return "OK"
        # return json.dumps({"status": "OK", "message":f"Sua mensagem, {nome}, foi enviada com sucesso!"})
        # return redirect(url_for('index'))
    return erros
    # return render_template("index.html", erros=erros)

