from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_mail import Mail, Message
from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import sqlite3
import re
import requests
import secrets

app = Flask(__name__)
app.secret_key = 'amerdadakey'
ph = PasswordHasher()

AES_KEY = b'amerdadaoutrakeyamerdadaoutrakey'  # 32 bytes

# Configurações do email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gustavoneves1003@gmail.com'
app.config['MAIL_PASSWORD'] = 'jgowkqvigobamoao'
app.config['MAIL_DEFAULT_SENDER'] = 'gustavoneves1003@gmail.com'
mail = Mail(app)

def conectar_bd():
    return sqlite3.connect('banco.db')

def validar_usuario(usuario):
    return 3 <= len(usuario) <= 15

def validar_senha(senha):
    return (
        len(senha) >= 8 and
        re.search(r'[A-Z]', senha) and
        re.search(r'[0-9]', senha) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', senha)
    )

def criptografar_aes(texto):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(texto.encode('utf-8'))
    dados = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
    return dados

def descriptografar_aes(dados):
    try:
        dados = base64.b64decode(dados)
        nonce = dados[:16]
        tag = dados[16:32]
        ciphertext = dados[32:]
        cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
        texto = cipher.decrypt(ciphertext)
        cipher.verify(tag)  # Garante que não foi alterado
        return texto.decode('utf-8')
    except Exception as e:
        print("Erro ao descriptografar:", e)
        return '[Erro ao descriptografar]'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']

        con = conectar_bd()
        cursor = con.cursor()
        cursor.execute(f"SELECT senha FROM usuarios WHERE usuario = '{usuario}'")
        resultado = cursor.fetchone()
        con.close()

        if resultado:
            senha_hash = resultado[0]
            try:
                if ph.verify(senha_hash, senha):
                    session['usuario'] = usuario
                    resp = make_response(redirect(url_for('dashboard')))
                    resp.set_cookie('usuario', usuario, max_age=3600)  # Cookie válido por 1 hora
                    return resp
            except:
                pass
        return render_template('login.html', erro="Usuário ou senha incorretos")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        email = request.form['email']

        if not validar_usuario(usuario) or not validar_senha(senha):
            flash("Senha ou usuário inválidos.", 'danger')
            return redirect(request.url)

        senha_hash = ph.hash(senha)
        con = conectar_bd()
        cursor = con.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
        if cursor.fetchone():
            con.close()
            return render_template('registro.html', erro="Usuário já existe.")

        cursor.execute("INSERT INTO usuarios (usuario, senha, email) VALUES (?, ?, ?)", (usuario, senha_hash, email))
        con.commit()
        con.close()

        return redirect(url_for('login'))

    return render_template('registro.html')

@app.route('/add_senha', methods=['POST'])
def add_senha():
    if 'usuario' not in session:
        return redirect('/login')

    site = request.form.get('site')
    senha = request.form.get('senha')
    usuario = session['usuario']

    if not site or not senha:
        flash("Preencha todos os campos!", "danger")
        return redirect(url_for('dashboard'))

    try:
        senha_encriptada = criptografar_aes(senha)
        with sqlite3.connect('banco.db', timeout=10) as con:
            cursor = con.cursor()
            cursor.execute("INSERT INTO senhas (usuario, site, senha) VALUES (?, ?, ?)",
                           (usuario, site, senha_encriptada))
            con.commit()
        flash("Senha salva com sucesso!", "success")
    except sqlite3.OperationalError as e:
        flash(f"Erro de banco de dados: {e}", "danger")

    return redirect(url_for('dashboard'))

@app.route("/dashboard")
def dashboard():
    if "usuario" not in session:
        usuario_cookie = request.cookies.get("usuario")
        if not usuario_cookie:
            return redirect("/login")
        session["usuario"] = usuario_cookie  # restaura a sessão a partir do cookie

    usuario = session["usuario"]
    termo_busca = request.args.get("busca", "").strip()

    con = sqlite3.connect("banco.db")
    cursor = con.cursor()

    if termo_busca:
        cursor.execute("SELECT site, senha FROM senhas WHERE usuario = ? AND site LIKE ?", (usuario, f"%{termo_busca}%"))
    else:
        cursor.execute("SELECT site, senha FROM senhas WHERE usuario = ?", (usuario,))

    senhas_cruas = cursor.fetchall()
    con.close()

    senhas = []
    for site, senha_encriptada in senhas_cruas:
        senha_decodificada = descriptografar_aes(senha_encriptada)
        senhas.append((site, senha_decodificada))

    return render_template("dashboard.html", usuario=usuario, senhas=senhas)
# Meu Deus me ajuda 
@app.route('/logout')
def logout():
    session.pop('usuario', None)
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('usuario', '', expires=0)  
    return resp

@app.route('/excluir_senha', methods=['POST'])
def excluir_senha_route():
    data = request.get_json()
    site = data.get('site')
    if site:
        conn = sqlite3.connect('banco.db') 
        cursor = conn.cursor()
        cursor.execute("DELETE FROM senhas WHERE site = ?", (site,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'erro'}), 400

@app.route('/editar_senha', methods=['POST'])
def editar_senha_route():
    data = request.get_json()
    site = data.get('site')
    nova_senha = data.get('nova_senha')
    if site and nova_senha:
        try:
            nova_criptografada = criptografar_aes(nova_senha)
            conn = sqlite3.connect('banco.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE senhas SET senha = ? WHERE site = ?", (nova_criptografada, site))
            conn.commit()
            conn.close()
            return jsonify({'status': 'ok'})
        except Exception:
            return jsonify({'status': 'erro'}), 500
    return jsonify({'status': 'erro'}), 400

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        email = request.form.get('email')
        con = conectar_bd()
        cursor = con.cursor()
        cursor.execute("SELECT usuario FROM usuarios WHERE email = ?", (email,))
        resultado = cursor.fetchone()

        if resultado:
            usuario = resultado[0]
            token = secrets.token_urlsafe(16)
            cursor.execute("UPDATE usuarios SET token = ? WHERE email = ?", (token, email))
            con.commit()

            link = url_for('redefinir_senha', token=token, _external=True)
            msg = Message('Recuperação de Conta - Gerenciador de Senhas', recipients=[email])
            msg.body = f"Olá, {usuario}! Clique no link para redefinir sua senha: {link}"
            mail.send(msg)

            flash("Um e-mail foi enviado com instruções de recuperação.", "success")
        else:
            flash("E-mail não encontrado.", "danger")

        con.close()
        return redirect(url_for('recuperar'))

    return render_template('recuperar.html')

@app.route('/redefinir_senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    if request.method == 'POST':
        nova_senha = request.form.get('senha')
        confirmar = request.form.get('confirmar')

        if nova_senha != confirmar or not validar_senha(nova_senha):
            flash('As senhas não coincidem ou não são seguras.', 'danger')
            return redirect(request.url)

        nova_hash = ph.hash(nova_senha)

        con = sqlite3.connect('banco.db')
        cursor = con.cursor()
        cursor.execute("SELECT usuario FROM usuarios WHERE token = ?", (token,))
        resultado = cursor.fetchone()

        if resultado:
            usuario = resultado[0]
            cursor.execute("UPDATE usuarios SET senha = ?, token = NULL WHERE usuario = ?", (nova_hash, usuario))
            con.commit()
            con.close()
            flash('Senha redefinida com sucesso! Faça login com sua nova senha.', 'success')
            return redirect(url_for('login'))
        else:
            con.close()
            flash('Token inválido ou expirado.', 'danger')
            return redirect(url_for('recuperar'))

    return render_template('redefinir_senha.html', token=token)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

