import click
from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask.cli import with_appcontext
from connection import db
from model import User
from flask_login import LoginManager, login_user , logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
import os

# Configuração do aplicativo Flask
app = Flask(__name__)
app.secret_key = "abax"

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'  # Define a rota de login para redirecionar não autenticados
login_manager.init_app(app)

# Configuração do Flask-Bcrypt
bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
# Configure o URI do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def init_db():
    db.drop_all()
    #db.reflect() # Pega as tabelas criadas no model e joga no database
    print("criando banco") 
    db.create_all()

# Comando para inicializar o banco de dados
@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear existing data and create new tables."""

    init_db()
    click.echo("Initialized the database.")

app.cli.add_command(init_db_command)

# Configuração do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'  # Usando Mailtrap para testes
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'seu_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'sua_senha_do_email'
app.config['MAIL_DEFAULT_SENDER'] = 'seu_email@gmail.com'

mail = Mail(app)

# Configuração do login_manager para redirecionar para a página de login
login_manager.login_view = 'login'

# Carregando o usuário com base no ID
@login_manager.user_loader
def load_user(id):
    return User.get(id)

# Definição das rotas
@app.route("/index")
@app.route("/")
def index():
    if '_user_id' in session:
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
        user = User.query.filter_by(username=username).first()

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Verificar se as senhas coincidem
        if password != confirm_password:
            flash('As senhas não coincidem', 'error')
            return render_template('register.html')

        # Verificar se o username já existe
        if User.query.filter_by(username=username).first():
            flash('Este nome de usuário já está em uso.', 'error')
            return render_template('register.html')

        # Criptografar a senha
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Criar o usuário
        new_user = User(username=username, password=hashed_password, email = email)
        db.session.add(new_user)
        db.session.commit()

        flash('Conta criada com sucesso!', 'success')
        return redirect(url_for('login'))  # Redirecionar para a página de login após o registro bem-sucedido

    return render_template('register.html')

@app.route('/criar_nova_senha', methods=['GET', 'POST'])
def criar_nova_senha():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Verificar se as senhas coincidem
        if password != confirm_password:
            flash('As senhas não coincidem', 'error')
            return render_template('criar_nova_senha.html')

        # Verificar se o username ou o email já existe
        user = User.query.filter_by(username=username).first()  # Buscar o usuário pelo nome de usuário
        if not user:
            user = User.query.filter_by(email=email).first()  # Buscar o usuário pelo email, caso não tenha encontrado pelo username

        if user:
            # Se o usuário já existir, atualiza a senha
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()

            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('login'))  # Redirecionar para a página de login após a alteração da senha
        else:
            # Se o usuário não existir vai exibir uma mensagem de erro
            flash('Usuário não encontrado.', 'error')
            return render_template('criar_nova_senha.html')

    return render_template('criar_nova_senha.html')

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

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0") # executa o flask na porta http://127.0.0.1:5000