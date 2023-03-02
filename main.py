import flask
import time
from datetime import datetime
import json
from flask_socketio import SocketIO, emit, rooms, disconnect
import secrets
import hashlib
import os
from database import DB
import commands
from commands_folder.mcb_db import database as mcb_db_database
import threading

session_db = None
known_clients_db = None

enter_callback_queue = {}
commands_mcb_db = None
with open(".config.json") as f:
    config = json.loads(f.read())
    is_production = config['is_production']
    ssl_context = config['ssl_context']
    if isinstance(ssl_context, list):
        ssl_context = tuple(ssl_context)

def log(type, message):
    now = datetime.now()
    timestamp = now.strftime("%m/%d/%Y %H:%M:%S")
    log_msg = f"{timestamp} - [{type}] {message}"
    with open("security_databases/log.txt", "a") as f:
        f.write(log_msg+"\n")
    print(log_msg)

def client_log_auth_success(ip_addr, user_agent, username, auto_login=False):
    if known_clients_db.get(ip_addr) == None:
        known_clients_db[ip_addr] = {"logins": [], "failed_attempts": []}
    if known_clients_db[ip_addr]['logins'] == None:
        known_clients_db[ip_addr]['logins'] = []
    d = {
            "user_agent": user_agent,
            "username": username,
            "timestamp": int(time.time())
        }
    if auto_login == True:
        d['auto_login'] = True
    known_clients_db[ip_addr]['logins'].append(d)
    known_clients_db.update(ip_addr, {'failed_attempt_count': 0})
    known_clients_db.update(ip_addr, {'last_successful_login': int(time.time())})

def client_log_auth_failure(ip_addr, user_agent, username):
    if known_clients_db.get(ip_addr) == None:
        known_clients_db[ip_addr] = {"logins": [], "failed_attempts": []}
    if known_clients_db[ip_addr]['failed_attempts'] == None:
        known_clients_db[ip_addr]['failed_attempts'] = []
    known_clients_db[ip_addr]['failed_attempts'].append({
            "user_agent": user_agent,
            "username": username,
            "timestamp": int(time.time())
        })
    if known_clients_db[ip_addr].get("failed_attempt_count") == None:
        known_clients_db.update(ip_addr, {'failed_attempt_count': 1})
    else:
        known_clients_db.update(ip_addr, {'failed_attempt_count': known_clients_db[ip_addr]['failed_attempt_count']+1})
    known_clients_db.update(ip_addr, {'last_failed_attempt': int(time.time())})

class FlaskApp(flask.Flask):
    def run(self, host=None, port=None, debug=None, load_dotenv=True, **options):
        global session_db
        global known_clients_db
        global commands_mcb_db
        if not self.debug or os.getenv('WERKZEUG_RUN_MAIN') == 'true':
            session_db = DB("security_databases/session_db")
            for key, _ in session_db:
                session_db.pop(key)
            known_clients_db = DB("security_databases/known_clients")
            commands_mcb_db = {
                "dal": mcb_db_database.DB("commands_folder/mcb_db/dal_db"),
                "ryankndl": mcb_db_database.DB("commands_folder/mcb_db/ryankndl_db"),
                "dsehyd": mcb_db_database.DB("commands_folder/mcb_db/dsehyd_db")
                }
        super(FlaskApp, self).run(host=host, port=port, debug=debug, load_dotenv=load_dotenv, **options)

if is_production == False:
    app = FlaskApp(__name__, static_url_path='', static_folder='static')
else:
    app = flask.Flask(__name__, static_url_path='', static_folder='static')
    session_db = DB("security_databases/session_db")
    for key, _ in session_db:
        session_db.pop(key)
    known_clients_db = DB("security_databases/known_clients")
    commands_mcb_db = mcb_db_database.DB("commands_folder/mcb_db/database")
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app)

@app.route('/')
def home():
    return flask.render_template("home.html")

@socketio.on("connect")
def ws_connect():
    ip_addr = flask.request.remote_addr
    if flask.request.headers.get('X-Forwarded-For') != None:
        ip_addr = flask.request.headers['X-Forwarded-For']
    kc_data = known_clients_db.get(ip_addr)
    if kc_data != None:
        if kc_data.get("is_blacklisted") == True:
            emit("auth", {
                    "auto_auth": True,
                    "success": False,
                    "message": "\\nConnecting IP is &cred&BLACKLISTED&ec&."
                })
            return
        if kc_data.get("is_trusted") == True:
            emit("auth", {
                    "auto_auth": True,
                    "success": True,
                    "message": "\\nConnecting IP is recognized as &cgreen&TRUSTED&ec&.\\n"
                })

@socketio.on("disconnect")
def ws_connect():
    session_sid = rooms()[0]
    if session_db.get(session_sid) != None:
        ip_addr = flask.request.remote_addr
        if flask.request.headers.get('X-Forwarded-For') != None:
            ip_addr = flask.request.headers['X-Forwarded-For']
        username = session_db[session_sid]['username']
        log("AUTH", f"Disconnect request by {ip_addr} as user '{username}'")
        session_db.pop(session_sid)

def terminal_print(text, end="\\n"):
    emit("terminal", {"type": "stdout", "stdout": str(text)+end})

def terminal_exit():
    emit("terminal", {"type": "control", "command": "exit"})

def terminal_input(text="", pwd_mode=False):
    terminal_print(text, "")
    enter_callback_queue[flask.request.sid] = {"event": threading.Event()}
    emit("terminal", {"type": "control", "command": "enter_callback", "pwd_mode": pwd_mode})
    enter_callback_queue[flask.request.sid]["event"].wait()
    return_text = enter_callback_queue[flask.request.sid]["text"]
    enter_callback_queue.pop(flask.request.sid)
    return return_text

def terminal_js_execute(exec_command):
    emit("terminal", {"type": "js-exec", "js-command": exec_command})

def generate_splash_text():
    with open("security_databases/log.txt") as f:
        logs = f.read()
    logs = "\n".join(logs.split('\n')[-10:])
    return "Logs:\n"+logs

@socketio.on("auth")
def ws_auth(data):
    session_sid = rooms()[0]
    ip_addr = flask.request.remote_addr
    if flask.request.headers.get('X-Forwarded-For') != None:
        ip_addr = flask.request.headers['X-Forwarded-For']
    user_agent = flask.request.headers['User-Agent']
    username = data['username'].strip().lower()
    if data['password'] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        # AUTO LOGIN USED, no password given
        # above hash is calculated for "null" or "undefined" on client i think.
        kc_data = known_clients_db.get(ip_addr)
        if kc_data != None:
            if kc_data.get('is_blacklisted') == True:
                client_log_auth_failure(ip_addr, user_agent, username)
                log("AUTH", f"Failed login attempt by BLACKLISTED IP {ip_addr} as '{username}'")
                emit("auth", {"success": False})
                return
            if kc_data.get('is_trusted') == True:
                session_db[session_sid] = {
                        "user_agent": user_agent,
                        "ip_addr": ip_addr,
                        "username": username,
                        "login_timestamp": int(time.time())
                    }
                client_log_auth_success(ip_addr, user_agent, username, True)
                log("AUTH", f"Passwordless log on successful by {ip_addr} as '{username}' (TRUSTED IP)")
                emit("auth", {"success": True, "splash_text": generate_splash_text()})
                return
    password = hashlib.sha256(data['password'].encode()).hexdigest()
    with open(".passwd") as f:
        saved_passwd = json.loads(f.read()).get(username)
    if password == saved_passwd:
        session_db[session_sid] = {
                "user_agent": user_agent,
                "ip_addr": ip_addr,
                "username": username,
                "login_timestamp": int(time.time())
            }
        client_log_auth_success(ip_addr, user_agent, username)
        log("AUTH", f"Log on successful by {ip_addr} as '{username}'")
        emit("auth", {"success": True, "splash_text": generate_splash_text()})
    else:
        client_log_auth_failure(ip_addr, user_agent, username)
        attempts = known_clients_db[ip_addr]["failed_attempt_count"]
        log("AUTH", f"Failed login attempt by {ip_addr} as '{username}', attempt: {attempts}")
        emit("auth", {"success": False})
    return

@socketio.on("terminal")
def ws_terminal(data):
    if session_db.get(flask.request.sid) == None:
        return
    if data["type"] == "command":
        exec = data['exec']
        args = data['args']
        commands.handler(exec, args, globals())
    elif data["type"] == "enter_callback":
        enter_callback_queue[flask.request.sid]["text"] = data['text']
        enter_callback_queue[flask.request.sid]["event"].set()

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=8531, debug=not is_production, ssl_context=ssl_context)
