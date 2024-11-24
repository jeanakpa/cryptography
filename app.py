# serveur.py

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, send
import secrets
import random
from sympy import isprime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app)

connected_users = {}

# --- Fonctions de cryptage RSA ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message_rsa(message, public_key):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_message_rsa(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

# --- Fonctions de cryptage ElGamal ---
def generate_large_prime(bits=256):
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def generate_elgamal_keys(bits=256):
    p = generate_large_prime(bits)
    g = random.randint(2, p - 2)
    private_key = random.randint(1, p - 2)
    public_key = pow(g, private_key, p)
    return (p, g, public_key, private_key)

def elgamal_encrypt(message, p, g, public_key):
    m = int.from_bytes(message.encode(), 'big')
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(public_key, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, p, private_key):
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    message_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    return message_bytes.decode()

# --- Gestion des connexions des utilisateurs ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

# WebSocket events (exemple pour les utilisateurs connectés)
@socketio.on('connect')
def handle_connect():
    print("Un utilisateur s'est connecté.")
    

@socketio.on('disconnect')
def handle_disconnect():
    user_id = request.sid
    if user_id in connected_users:
        del connected_users[user_id]
        socketio.emit('user_list', [user['username'] for user in connected_users.values()])


@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    if username:
        user_id = request.sid
        # Génération des clés RSA et ElGamal pour chaque utilisateur
        rsa_private_key, rsa_public_key = generate_rsa_keys()
        p, g, elgamal_public_key, elgamal_private_key = generate_elgamal_keys()
        connected_users[user_id] = {
            'username': username,
            'rsa_keys': {'public_key': rsa_public_key, 'private_key': rsa_private_key},
            'elgamal_keys': {'p': p, 'g': g, 'public_key': elgamal_public_key, 'private_key': elgamal_private_key}
        }
        
        # Envoyer les informations de la clé ElGamal à l'utilisateur
        socketio.emit('elgamal_keys', {
            'p': p,
            'g': g,
            'public_key': elgamal_public_key
        }, room=user_id)
        
        socketio.emit('user_list', [user['username'] for user in connected_users.values()])

@socketio.on('send_message')
def handle_message(data):
    recipient_name = data['recipient']
    message = data['message']
    encryption_method = data['encryption_method']

    # Trouver le destinataire
    recipient_sid = None
    recipient_keys = None
    for sid, user_data in connected_users.items():
        if user_data['username'] == recipient_name:
            recipient_sid = sid
            recipient_keys = user_data
            break

    if not recipient_keys:
        return

    if encryption_method == 'RSA':
        encrypted_message = encrypt_message_rsa(message, recipient_keys['rsa_keys']['public_key'])
        encrypted_message_str = encrypted_message.hex()
        public_key_info = recipient_keys['rsa_keys']['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    elif encryption_method == 'ElGamal':
        encrypted_message = elgamal_encrypt(message, recipient_keys['elgamal_keys']['p'], recipient_keys['elgamal_keys']['g'], recipient_keys['elgamal_keys']['public_key'])
        encrypted_message_str = str(encrypted_message)
        public_key_info = f"p: {recipient_keys['elgamal_keys']['p']}, g: {recipient_keys['elgamal_keys']['g']}, public_key: {recipient_keys['elgamal_keys']['public_key']}"
    else:
        return

    # Diffuser le message à tous les utilisateurs
    socketio.emit('receive_message', {
        'sender': connected_users[request.sid]['username'],
        'encrypted_message': encrypted_message_str,
        'encryption_method': encryption_method,
        'public_key': public_key_info,
        'recipient': recipient_name  # Indiquer le destinataire
    })


@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    encrypted_message = data['message']
    encryption_method = data['encryption_method']
    user_data = connected_users[request.sid]

    # Effectuer le déchiffrement en fonction de la méthode
    if encryption_method == 'RSA':
        encrypted_message_bytes = bytes.fromhex(encrypted_message)
        decrypted_message = decrypt_message_rsa(encrypted_message_bytes, user_data['rsa_keys']['private_key'])
    elif encryption_method == 'ElGamal':
        # Conversion de la chaîne de tuple en un tuple réel pour déchiffrement
        encrypted_message_tuple = eval(encrypted_message)
        decrypted_message = elgamal_decrypt(encrypted_message_tuple, user_data['elgamal_keys']['p'], user_data['elgamal_keys']['private_key'])
    else:
        decrypted_message = "Méthode de déchiffrement non supportée."

    # Envoi du message déchiffré au client
    socketio.emit('decrypted_message', {'message': decrypted_message}, room=request.sid)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
