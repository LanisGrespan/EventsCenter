from sqlalchemy import Column, String, Integer, Double, DateTime
from connection import db
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

# Definições dos modelos
class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)

    @staticmethod
    def get(user_id):
        return User.query.get(int(user_id))

    def check_password(self, password):
        """Verifica se a senha fornecida corresponde à senha armazenada."""
        return bcrypt.check_password_hash(self.password, password)


class Inscricao(db.Model):
    __tablename__ = "inscricoes"

    id_inscricao = Column(Integer, primary_key=True, autoincrement=True)
    nome = Column(String, nullable=False)
    email = Column(String, nullable=False)
    cpf = Column(String, nullable=False)
    idade = Column(String, nullable=False)
    evento = Column(String, nullable=False)
    data = Column(DateTime, default=datetime.now())
    valor = Column(Double, nullable=False)
    telefone = Column(String, nullable=False)

class Contato(db.Model):
    __tablename__ = "contatos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    nome = Column(String, nullable=False)
    email = Column(String, nullable=False)
    assunto = Column(String, nullable=False)
    mensagem = Column(String, nullable=False)