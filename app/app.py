from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import random
import string
from datetime import datetime, timedelta
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'cle-secrete-super-securisee'  # Remplace par une clé secrète plus sécurisée

# ✅ Configuration Mailtrap
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'e4cd752b672bce'     # Ton identifiant Mailtrap
app.config['MAIL_PASSWORD'] = 'xxxxxx5920'         # Ton mot de passe Mailtrap
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@yourapp.com'

mail = Mail(app)

DATABASE = 'app/database.db'
LOGIN_ATTEMPTS = {}
BLOCK_DURATION = timedelta(minutes=5)

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        nom TEXT NOT NULL,
                        prenom TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        reset_code TEXT
                    )''')
        conn.commit()
        conn.close()

@app.before_request
def initialize():
    init_db()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        if len(password) < 8 or password.isalpha() or password.isdigit():
            flash("Le mot de passe doit contenir au moins 8 caractères avec lettres et chiffres.")
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        try:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("INSERT INTO users (nom, prenom, email, username, password) VALUES (?, ?, ?, ?, ?)",
                      (nom, prenom, email, username, hashed_pw))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Nom d'utilisateur ou email déjà utilisé.")
            return redirect(url_for('signup'))
        finally:
            conn.close()

        session['username'] = username
        flash("Inscription réussie. Vous êtes maintenant connecté.")
        return redirect(url_for('calculate'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    now = datetime.now()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in LOGIN_ATTEMPTS and now < LOGIN_ATTEMPTS[username]['blocked_until']:
            flash("Trop de tentatives échouées. Réessayez après 5 minutes.")
            return redirect(url_for('login'))

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session['username'] = username
            LOGIN_ATTEMPTS.pop(username, None)
            return redirect(url_for('calculate'))
        else:
            attempts = LOGIN_ATTEMPTS.get(username, {'count': 0, 'blocked_until': now})
            attempts['count'] += 1
            if attempts['count'] >= 3:
                attempts['blocked_until'] = now + BLOCK_DURATION
                flash("Mot de passe incorrect 3 fois. Réessayez après 5 minutes.")
            else:
                flash("Nom d'utilisateur ou mot de passe incorrect.")
            LOGIN_ATTEMPTS[username] = attempts
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        print(f"Email reçu du formulaire: {email}")  # Débogage

        code = ''.join(random.choices(string.digits, k=6))

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT email FROM users WHERE email = ?", (email,))
        row = c.fetchone()

        if row:
            print(f"Utilisateur trouvé pour l'email: {email}")  # Débogage

            c.execute("UPDATE users SET reset_code = ? WHERE email = ?", (code, email))
            conn.commit()
            conn.close()

            # Vérification de la mise à jour du code dans la base de données
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute("SELECT reset_code FROM users WHERE email = ?", (email,))
            updated_code = c.fetchone()
            print(f"Code mis à jour dans la base de données: {updated_code[0]}")  # Débogage
            conn.close()

            # Envoi de l'email avec le code
            msg = Message('Code de réinitialisation de mot de passe', recipients=[email])
            msg.body = f"Voici votre code de réinitialisation : {code}"
            try:
                mail.send(msg)
                flash(f"Un code a été envoyé à votre email.")
            except Exception as e:
                flash(f"Erreur lors de l'envoi de l'email : {str(e)}")
                return redirect(url_for('forgot'))

            session['reset_email'] = email
            return redirect(url_for('verify_code'))
        else:
            flash("Aucun utilisateur trouvé avec cet email.")
            conn.close()
            return redirect(url_for('forgot'))
    return render_template('forgot.html')

@app.route('/verify-code', methods=['GET', 'POST'])
def verify_code_view():
    if request.method == 'POST':
        code = request.form['code']
        email = session.get('reset_email')
        print(f"Code reçu du formulaire: {code}, Email de session: {email}")  # Débogage

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT reset_code FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()

        if row:
            print(f"Code dans la base de données: {row[0]}")  # Débogage

        if row and row[0] == code:
            flash("Code valide ! Vous pouvez maintenant réinitialiser votre mot de passe.")
            return redirect(url_for('reset'))
        flash("Code incorrect.")
    return render_template('verify_code.html')



@app.route('/verify-code', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        code = request.form['code']
        email = session.get('reset_email')
        print(f"Code reçu: {code}, Email de session: {email}")  # Débogage

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT reset_code FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()

        if row:
            print(f"Code dans la base de données: {row[0]}")  # Débogage

        if row and row[0] == code:
            return redirect(url_for('reset'))
        flash("Code incorrect.")
    return render_template('verify_code.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        password = request.form['password']
        if len(password) < 8 or password.isalpha() or password.isdigit():
            flash("Le mot de passe doit contenir au moins 8 caractères avec lettres et chiffres.")
            return redirect(url_for('reset'))

        email = session.get('reset_email')
        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("UPDATE users SET password = ?, reset_code = NULL WHERE email = ?", (hashed_pw, email))
        conn.commit()
        conn.close()
        flash("Mot de passe réinitialisé.")
        return redirect(url_for('login'))
    return render_template('reset.html')

@app.route('/calculate', methods=['GET', 'POST'])
def calculate():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            xA = float(request.form['xA'])  # Valeur xA
            xB = float(request.form['xB'])  # Valeur xB

            if abs(xA + xB - 1) > 1e-6:
                flash("La somme de xA et xB doit être égale à 1.")
                return redirect(url_for('calculate'))

            # Définition des variables pour le calcul
            D_AB_0_A = 2.1e-5
            D_AB_0_B = 2.67e-5
            phi_A = 0.279
            phi_B = 0.721
            lambda_A = 1.127
            lambda_B = 0.973
            q_A = 1.432
            q_B = 1.4
            theta_BA = 0.612
            theta_BB = 0.739
            theta_AB = 0.261
            theta_AA = 0.388
            tau_BA = 0.5373
            tau_AB = 1.035
            D_AB_reference = 1.33e-5

            # Calcul des termes
            import numpy as np
            term1 = xB * np.log(D_AB_0_A) + xA * np.log(D_AB_0_B)
            term2 = 2 * (xA * np.log(xA / phi_A) + xB * np.log(xB / phi_B))
            term3 = 2 * xA * xB * ((phi_A / xA) * (1 - (lambda_A / lambda_B)) + (phi_B / xB) * (1 - (lambda_B / lambda_A)))
            term4 = (xB * q_A) * ((1 - theta_BA ** 2) * np.log(tau_BA) + (1 - theta_BB **2) * tau_AB * np.log(tau_AB))
            term5 = (xA * q_B) * ((1 - theta_AB ** 2) * np.log(tau_AB) + (1 - theta_AA ** 2) * tau_BA * np.log(tau_BA))

            # Calcul du ln(D_AB)
            ln_D_AB = term1 + term2 + term3 + term4 + term5
            D_AB_calcule = np.exp(ln_D_AB)
            erreur = abs((D_AB_calcule - D_AB_reference) / D_AB_reference) * 100

            return render_template('result.html', D_AB=D_AB_calcule, erreur=erreur)

        except Exception as e:
            flash(f"Erreur de calcul : {str(e)}")
            return redirect(url_for('calculate'))

    return render_template('calculate.html')

if __name__ == '__main__':
    app.run(debug=True)