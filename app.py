from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import bcrypt
import os
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = 'your_secret_key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '202130'
app.config['MYSQL_DB'] = 'flask_voting'

mysql = MySQL(app)

# User class to interact with MySQL database
class User:
    @staticmethod
    def add_user(username, password):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return False
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        mysql.connection.commit()
        cur.close()
        return True

    @staticmethod
    def authenticate(username, password):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            return user
        return None

    @staticmethod
    def has_voted(username):
        cur = mysql.connection.cursor()
        cur.execute("SELECT has_voted FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        cur.close()
        return result[0] if result else False

    @staticmethod
    def mark_voted(username):
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET has_voted = TRUE WHERE username = %s", (username,))
        mysql.connection.commit()
        cur.close()

# Voting System class
class VotingSystem:
    def vote(self, username, candidate_id):
        if User.has_voted(username):
            return "You have already voted."
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM candidates WHERE id = %s", (candidate_id,))
        if not cur.fetchone():
            cur.close()
            return "Invalid candidate."
        cur.execute("INSERT INTO votes (username, candidate_id) VALUES (%s, %s)", (username, candidate_id))
        mysql.connection.commit()
        User.mark_voted(username)
        cur.close()
        return "Vote cast successfully."

    def view_results(self):
        cur = mysql.connection.cursor()
        cur.execute("SELECT c.id, c.name, COUNT(v.id) as votes FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id GROUP BY c.id, c.name ORDER BY votes DESC")
        results = cur.fetchall()
        cur.close()
        return [{'id': row[0], 'name': row[1], 'votes': row[2]} for row in results]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register.html', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.add_user(username, password):
            flash("User registered successfully.", "success")
            return redirect(url_for('login'))
        else:
            flash("Username already exists.", "danger")
    return render_template('register.html')

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.authenticate(username, password)
        if user:
            session['username'] = username
            flash("Login successful.", "success")
            return redirect(url_for('vote'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/vote.html', methods=['GET', 'POST'])
def vote():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    voting_system = VotingSystem()
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name FROM candidates")
    candidates = [{'id': row[0], 'name': row[1]} for row in cur.fetchall()]
    cur.close()
    if request.method == 'POST':
        candidate_id = request.form['candidate']
        message = voting_system.vote(username, candidate_id)
        flash(message, "info")
        return redirect(url_for('index'))
    return render_template('vote.html', candidates=candidates)

@app.route('/results.html')
def results():
    if 'username' not in session:
        return redirect(url_for('login'))
    voting_system = VotingSystem()
    results = voting_system.view_results()
    return render_template('result.html', candidates=results)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin_logged_in'):
        flash('Please log in as admin to access the admin panel.', 'warning')
        return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    if request.method == 'POST':
        if 'remove_id' in request.form:
            remove_id = request.form['remove_id']
            cur.execute("DELETE FROM candidates WHERE id = %s", (remove_id,))
            mysql.connection.commit()
            flash('Candidate removed successfully.', 'info')
        elif 'name' in request.form:
            name = request.form['name']
            cur.execute("INSERT INTO candidates (name) VALUES (%s)", (name,))
            mysql.connection.commit()
    cur.execute("SELECT c.id, c.name, COUNT(v.id) as votes FROM candidates c LEFT JOIN votes v ON c.id = v.candidate_id GROUP BY c.id, c.name ORDER BY votes DESC")
    candidates = [{'id': row[0], 'name': row[1], 'votes': row[2]} for row in cur.fetchall()]
    cur.close()
    return render_template('admin.html', candidates=candidates)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin123':
            session['admin_logged_in'] = True
            flash('Admin logged in.', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/candidates_data')
def candidates_data():
    if not session.get('admin_logged_in'):
        flash('Please log in as admin to access candidate data.', 'warning')
        return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT username, has_voted FROM users")
    users = [{'username': row[0], 'has_voted': row[1]} for row in cur.fetchall()]
    cur.close()
    return render_template('candidates_data.html', users=users)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if not session.get('admin_logged_in'):
        flash('Please log in as admin to delete users.', 'warning')
        return redirect(url_for('admin_login'))
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE username = %s", (username,))
    mysql.connection.commit()
    cur.close()
    flash(f'User {username} deleted successfully.', 'info')
    return redirect(url_for('candidates_data'))

if __name__ == '__main__':
    app.run(debug=True)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)





