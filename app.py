#!/usr/bin/env python3
"""
Wake-on-LAN Web Interface para Orange Pi Zero
Permite ligar computadores remotamente via interface web.
Sistema multi-usuário com permissões por computador.
"""

import os
import sqlite3
import subprocess
import platform
import secrets
import hashlib
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g

app = Flask(__name__)

DATABASE = 'wol.db'


def get_db():
    """Obtém conexão com o banco de dados"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Fecha conexão com o banco ao final da requisição"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def hash_password(password):
    """Gera hash da senha"""
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    """Inicializa o banco de dados com as tabelas necessárias"""
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS computers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_computers (
            user_id INTEGER NOT NULL,
            computer_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, computer_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (computer_id) REFERENCES computers(id) ON DELETE CASCADE
        )
    ''')

    # Criar usuário admin padrão se não existir
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if cursor.fetchone() is None:
        cursor.execute(
            'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
            ('admin', hash_password('admin'), 1)
        )

    # Gerar chave secreta se não existir
    cursor.execute('SELECT value FROM settings WHERE key = ?', ('secret_key',))
    if cursor.fetchone() is None:
        secret = secrets.token_hex(32)
        cursor.execute('INSERT INTO settings (key, value) VALUES (?, ?)', ('secret_key', secret))

    db.commit()
    db.close()


def get_setting(key):
    """Obtém uma configuração do banco"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    return row['value'] if row else None


# ========== USERS ==========

def get_user_by_username(username):
    """Obtém usuário pelo username"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id):
    """Obtém usuário pelo ID"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_all_users():
    """Obtém todos os usuários"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, username, is_admin, created_at FROM users ORDER BY username')
    return [dict(row) for row in cursor.fetchall()]


def create_user(username, password, is_admin=False):
    """Cria um novo usuário"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
        (username, hash_password(password), 1 if is_admin else 0)
    )
    db.commit()
    return cursor.lastrowid


def update_user(user_id, username=None, password=None, is_admin=None):
    """Atualiza um usuário"""
    db = get_db()
    cursor = db.cursor()

    updates = []
    params = []

    if username:
        updates.append('username = ?')
        params.append(username)
    if password:
        updates.append('password = ?')
        params.append(hash_password(password))
    if is_admin is not None:
        updates.append('is_admin = ?')
        params.append(1 if is_admin else 0)

    if not updates:
        return False

    params.append(user_id)
    cursor.execute(f'UPDATE users SET {", ".join(updates)} WHERE id = ?', params)
    db.commit()
    return cursor.rowcount > 0


def delete_user(user_id):
    """Remove um usuário"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', (user_id,))
    db.commit()
    return cursor.rowcount > 0


# ========== COMPUTERS ==========

def get_all_computers():
    """Obtém todos os computadores"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM computers ORDER BY name')
    return [dict(row) for row in cursor.fetchall()]


def get_user_computers(user_id):
    """Obtém computadores do usuário (admin vê todos)"""
    db = get_db()
    cursor = db.cursor()

    user = get_user_by_id(user_id)
    if user and user['is_admin']:
        cursor.execute('SELECT * FROM computers ORDER BY name')
    else:
        cursor.execute('''
            SELECT c.* FROM computers c
            INNER JOIN user_computers uc ON c.id = uc.computer_id
            WHERE uc.user_id = ?
            ORDER BY c.name
        ''', (user_id,))

    return [dict(row) for row in cursor.fetchall()]


def get_computer(computer_id):
    """Obtém um computador pelo ID"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM computers WHERE id = ?', (computer_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def user_can_access_computer(user_id, computer_id):
    """Verifica se usuário tem acesso ao computador"""
    user = get_user_by_id(user_id)
    if user and user['is_admin']:
        return True

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'SELECT 1 FROM user_computers WHERE user_id = ? AND computer_id = ?',
        (user_id, computer_id)
    )
    return cursor.fetchone() is not None


def add_computer(name, mac, ip):
    """Adiciona um novo computador"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'INSERT INTO computers (name, mac, ip) VALUES (?, ?, ?)',
        (name, mac.upper(), ip)
    )
    db.commit()
    return cursor.lastrowid


def update_computer(computer_id, name, mac, ip):
    """Atualiza um computador existente"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'UPDATE computers SET name = ?, mac = ?, ip = ? WHERE id = ?',
        (name, mac.upper(), ip, computer_id)
    )
    db.commit()
    return cursor.rowcount > 0


def delete_computer(computer_id):
    """Remove um computador"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM computers WHERE id = ?', (computer_id,))
    db.commit()
    return cursor.rowcount > 0


# ========== PERMISSIONS ==========

def get_computer_users(computer_id):
    """Obtém usuários com acesso a um computador"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT u.id, u.username FROM users u
        INNER JOIN user_computers uc ON u.id = uc.user_id
        WHERE uc.computer_id = ?
    ''', (computer_id,))
    return [dict(row) for row in cursor.fetchall()]


def set_computer_users(computer_id, user_ids):
    """Define quais usuários têm acesso a um computador"""
    db = get_db()
    cursor = db.cursor()

    # Remove permissões antigas
    cursor.execute('DELETE FROM user_computers WHERE computer_id = ?', (computer_id,))

    # Adiciona novas permissões
    for user_id in user_ids:
        cursor.execute(
            'INSERT OR IGNORE INTO user_computers (user_id, computer_id) VALUES (?, ?)',
            (user_id, computer_id)
        )

    db.commit()


# ========== AUTH ==========

def login_required(f):
    """Decorator para proteger rotas que requerem autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator para proteger rotas que requerem admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            return jsonify({'success': False, 'message': 'Acesso negado'}), 403
        return f(*args, **kwargs)
    return decorated_function


def ping_host(ip):
    """Verifica se um host está online via ping"""
    if platform.system().lower() == 'windows':
        command = ['ping', '-n', '1', '-w', '1000', ip]
    else:
        command = ['ping', '-c', '1', '-W', '1', ip]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return False


@app.before_request
def load_secret_key():
    """Carrega a chave secreta do banco antes de cada requisição"""
    if not app.secret_key or app.secret_key == 'temporary':
        try:
            db = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row
            cursor = db.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', ('secret_key',))
            row = cursor.fetchone()
            if row:
                app.secret_key = row['value']
            db.close()
        except Exception:
            pass


@app.context_processor
def inject_user():
    """Injeta informações do usuário em todos os templates"""
    return {
        'current_user': {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'is_admin': session.get('is_admin', False)
        }
    }


# ========== ROUTES ==========

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(username)
        if user and user['password'] == hash_password(password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('index'))
        else:
            error = 'Usuário ou senha incorretos'

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Encerra a sessão do usuário"""
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    """Página principal com lista de computadores do usuário"""
    computers = get_user_computers(session['user_id'])
    return render_template('index.html', computers=computers)


@app.route('/config')
@admin_required
def config():
    """Página de configuração (CRUD de computadores) - somente admin"""
    computers = get_all_computers()
    users = get_all_users()
    return render_template('config.html', computers=computers, users=users)


@app.route('/config/computer', methods=['POST'])
@admin_required
def add_computer_route():
    """Adiciona um novo computador"""
    name = request.form.get('name', '').strip()
    mac = request.form.get('mac', '').strip()
    ip = request.form.get('ip', '').strip()

    if not all([name, mac, ip]):
        return jsonify({'success': False, 'message': 'Todos os campos são obrigatórios'}), 400

    try:
        computer_id = add_computer(name, mac, ip)
        return jsonify({'success': True, 'id': computer_id, 'message': 'Computador adicionado'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'MAC já cadastrado'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/config/computer/<int:computer_id>', methods=['PUT'])
@admin_required
def update_computer_route(computer_id):
    """Atualiza um computador existente"""
    data = request.get_json()
    name = data.get('name', '').strip()
    mac = data.get('mac', '').strip()
    ip = data.get('ip', '').strip()

    if not all([name, mac, ip]):
        return jsonify({'success': False, 'message': 'Todos os campos são obrigatórios'}), 400

    try:
        if update_computer(computer_id, name, mac, ip):
            return jsonify({'success': True, 'message': 'Computador atualizado'})
        return jsonify({'success': False, 'message': 'Computador não encontrado'}), 404
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'MAC já cadastrado'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/config/computer/<int:computer_id>', methods=['DELETE'])
@admin_required
def delete_computer_route(computer_id):
    """Remove um computador"""
    if delete_computer(computer_id):
        return jsonify({'success': True, 'message': 'Computador removido'})
    return jsonify({'success': False, 'message': 'Computador não encontrado'}), 404


@app.route('/config/computer/<int:computer_id>/users', methods=['GET'])
@admin_required
def get_computer_users_route(computer_id):
    """Obtém usuários com acesso a um computador"""
    users = get_computer_users(computer_id)
    return jsonify({'success': True, 'users': [u['id'] for u in users]})


@app.route('/config/computer/<int:computer_id>/users', methods=['POST'])
@admin_required
def set_computer_users_route(computer_id):
    """Define usuários com acesso a um computador"""
    data = request.get_json()
    user_ids = data.get('user_ids', [])
    set_computer_users(computer_id, user_ids)
    return jsonify({'success': True, 'message': 'Permissões atualizadas'})


# ========== USER MANAGEMENT ==========

@app.route('/config/user', methods=['POST'])
@admin_required
def add_user_route():
    """Adiciona um novo usuário"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    is_admin = data.get('is_admin', False)

    if not all([username, password]):
        return jsonify({'success': False, 'message': 'Usuário e senha são obrigatórios'}), 400

    try:
        user_id = create_user(username, password, is_admin)
        return jsonify({'success': True, 'id': user_id, 'message': 'Usuário criado'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Usuário já existe'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/config/user/<int:user_id>', methods=['PUT'])
@admin_required
def update_user_route(user_id):
    """Atualiza um usuário"""
    data = request.get_json()
    username = data.get('username', '').strip() or None
    password = data.get('password', '') or None
    is_admin = data.get('is_admin')

    try:
        if update_user(user_id, username, password, is_admin):
            return jsonify({'success': True, 'message': 'Usuário atualizado'})
        return jsonify({'success': False, 'message': 'Usuário não encontrado'}), 404
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Usuário já existe'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/config/user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user_route(user_id):
    """Remove um usuário (não pode remover admin)"""
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': 'Não pode remover a si mesmo'}), 400

    if delete_user(user_id):
        return jsonify({'success': True, 'message': 'Usuário removido'})
    return jsonify({'success': False, 'message': 'Usuário não encontrado ou é admin'}), 404


@app.route('/profile/password', methods=['POST'])
@login_required
def change_own_password():
    """Permite que qualquer usuário altere sua própria senha"""
    data = request.get_json()
    current = data.get('current', '')
    new_password = data.get('new', '')

    if not new_password:
        return jsonify({'success': False, 'message': 'Nova senha é obrigatória'}), 400

    user = get_user_by_id(session['user_id'])
    if not user or user['password'] != hash_password(current):
        return jsonify({'success': False, 'message': 'Senha atual incorreta'}), 400

    update_user(session['user_id'], password=new_password)
    return jsonify({'success': True, 'message': 'Senha alterada com sucesso'})


# ========== WAKE ON LAN ==========

@app.route('/wake/<mac>', methods=['POST'])
@login_required
def wake(mac):
    """Envia pacote Wake-on-LAN para o MAC especificado"""
    # Verificar se usuário tem acesso a este computador
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM computers WHERE mac = ?', (mac.upper(),))
    computer = cursor.fetchone()

    if not computer:
        return jsonify({'success': False, 'message': 'Computador não encontrado'}), 404

    if not user_can_access_computer(session['user_id'], computer['id']):
        return jsonify({'success': False, 'message': 'Acesso negado'}), 403

    try:
        from wakeonlan import send_magic_packet
        mac_clean = mac.replace('-', ':').upper()
        send_magic_packet(mac_clean)
        return jsonify({'success': True, 'message': f'Pacote WoL enviado para {mac}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/status')
@login_required
def status():
    """Retorna o status online/offline dos computadores do usuário"""
    computers = get_user_computers(session['user_id'])
    statuses = {}

    for computer in computers:
        ip = computer.get('ip')
        mac = computer.get('mac')
        if ip and mac:
            statuses[mac] = ping_host(ip)

    return jsonify(statuses)


if __name__ == '__main__':
    init_db()
    app.secret_key = 'temporary'
    app.run(host='0.0.0.0', port=5000, debug=False)
