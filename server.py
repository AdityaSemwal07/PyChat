import time
import json
import socket
import requests
import threading
import subprocess
import mysql.connector
from bottle import Bottle, response

# ---------------------- MySQL Database Setup ----------------------

# Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="password@123",  # Replace with your MySQL root password
)
cursor = db.cursor()

# Create and use 'pychat' database
cursor.execute("CREATE DATABASE IF NOT EXISTS pychat")
cursor.execute("USE pychat")

# Table to store unique chat rooms
cursor.execute("""
CREATE TABLE IF NOT EXISTS chats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
)
""")

# Table to store messages with sender, content, and timestamp
cursor.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chat_name VARCHAR(255),
    sender VARCHAR(255),
    content TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# Table to store user credentials and online status
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    online BOOLEAN DEFAULT FALSE
)
""")

# Set all users offline when server starts
cursor.execute("UPDATE users SET online=FALSE")
db.commit()

# ---------------------- Server & Ngrok Configuration ----------------------

HOST = '127.0.0.1'
PORT = 1060

ngrok_info = {}

# Start ngrok in background using subprocess
p = subprocess.Popen(['ngrok', 'start', '--all'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

# Function to fetch ngrok public URLs
def check_ngrok():
    global ngrok_info
    time.sleep(.5)
    res = requests.get("http://127.0.0.1:4040/api/tunnels")
    tunnellist = res.json()["tunnels"]
    tcp_url = ""
    web_url = ""

    if not tunnellist:
        check_ngrok()
    else:
        for t in tunnellist:
            if t["name"] == "pychattcp":
                tcp_url = t["public_url"]
                ngrok_info = {
                    "name": "pychattcp",
                    "public_url": tcp_url,
                    "config": t["config"]
                }
            elif t["name"] == "pychatweb":
                web_url = t["public_url"]
        print(f"[+] HTTP Tunnel: {web_url} -> http://127.0.0.1:3300")
        print(f"[+] TCP Tunnel: {tcp_url} -> http://127.0.0.1:1060")

check_ngrok()

# ---------------------- Flask API Server ----------------------

app = Bottle()

# Endpoint to serve ngrok public URL to clients

@app.get("/")
def get_info():
    response.content_type = 'application/json'
    return json.dumps(ngrok_info)

# Run Flask in a background thread
def run_bottle():
    app.run(port=3300)

flask_thread = threading.Thread(target=run_bottle, daemon=True)
flask_thread.start()

# ---------------------- Chat Server Logic ----------------------

clients = {}     # Mapping of socket -> (username, chat_name)
chats = {}       # Mapping of chat_name -> list of client sockets

# Ensure chat room exists in DB
def ensure_chat_exists(chat_name):
    cursor.execute("SELECT id FROM chats WHERE name = %s", (chat_name,))
    if not cursor.fetchone():
        cursor.execute("INSERT INTO chats (name) VALUES (%s)", (chat_name,))
        db.commit()

# Load old chat messages from DB
def load_chat_history(chat_name):
    cursor.execute("""
    SELECT sender, content FROM messages
    WHERE chat_name = %s
    ORDER BY timestamp ASC
    """, (chat_name,))
    return cursor.fetchall()

# Save message to DB
def save_message(chat_name, sender, content):
    cursor.execute("""
    INSERT INTO messages (chat_name, sender, content)
    VALUES (%s, %s, %s)
    """, (chat_name, sender, content))
    db.commit()

# Broadcast message to all clients in the chat
def broadcast(message, chat_name):
    if chat_name in chats:
        for client in chats[chat_name]:
            try:
                client.send((message + "\n").encode())
            except:
                # Clean up disconnected clients
                client.close()
                if client in chats[chat_name]:
                    chats[chat_name].remove(client)

# Handle individual client connection
def handle_client(client_socket):
    username = ''
    try:
        # Authenticate user
        auth = client_socket.recv(1024).decode()
        if not auth.startswith("/auth|"):
            client_socket.send("ERROR: Invalid authentication format.\n".encode())
            client_socket.close()
            return

        _, username, password = auth.split("|")

        cursor.execute("SELECT password, online FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()
        if row:
            stored_password, online = row
            if online:
                client_socket.send("ERROR: User is online already.\n".encode())
                client_socket.close()
                return
            if stored_password != password:
                client_socket.send("ERROR: Invalid password.\n".encode())
                client_socket.close()
                return
            # Mark user as online
            cursor.execute("UPDATE users SET online = TRUE WHERE username = %s", (username,))
        else:
            # Register new user
            cursor.execute("INSERT INTO users (username, password, online) VALUES (%s, %s, TRUE)",
                           (username, password))

        db.commit()
        client_socket.send("LOGIN_SUCCESS\n".encode())

        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break

            # Join chat command
            if data.startswith("/join"):
                _, username, chat, lchat = data.split("|")
                ensure_chat_exists(chat)
                clients[client_socket] = (username, chat)
                if client_socket not in chats.setdefault(chat, []):
                    if not lchat:
                        chats[chat].append(client_socket)
                    else:
                        chats[lchat].remove(client_socket)
                        chats[chat].append(client_socket)
                print(f"[+] {username} joined chat '{chat}'")

                # Send chat history to client
                history = load_chat_history(chat)
                for sender, msg in history:
                    formatted = f"{sender}: {msg}\n"
                    client_socket.send(formatted.encode())
                continue

            # Receive and broadcast message
            username, chat, msg = data.split("|", 2)
            save_message(chat, username, msg)
            full_msg = f"{username}: {msg}"
            broadcast(full_msg, chat)

    except ConnectionResetError:
        print(f"[!] {username} disconnected abruptly.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        # Clean up user from chat and mark offline
        if client_socket in clients:
            _, chat = clients[client_socket]
            print(f"[-] {username} left chat '{chat}'")
            if chat in chats and client_socket in chats[chat]:
                chats[chat].remove(client_socket)
            del clients[client_socket]

        if username:
            try:
                cursor.execute("UPDATE users SET online = FALSE WHERE username = %s", (username,))
                db.commit()
            except Exception as e:
                print(f"[!] Failed to update online status: {e}")
        
        client_socket.close()

# ---------------------- Start Server ----------------------

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")

try:
    while True:
        client_socket, addr = server.accept()
        print(f"[NEW CONNECTION] {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket,), daemon=True)
        thread.start()
except:
    # Terminate ngrok when server exits
    p.terminate()