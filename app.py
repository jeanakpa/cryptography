from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import random
from sympy import isprime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

connected_users = {}

# --- RSA Encryption ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(message, public_key):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_rsa(ciphertext, private_key):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

# --- ElGamal Encryption ---
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

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

# --- WebSocket Events ---
@socketio.on('register')
def register(data):
    username = data['username']
    user_id = request.sid

    # Generate RSA and ElGamal keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    p, g, elgamal_public_key, elgamal_private_key = generate_elgamal_keys()

    connected_users[user_id] = {
        'username': username,
        'rsa_keys': {'public_key': rsa_public_key, 'private_key': rsa_private_key},
        'elgamal_keys': {'p': p, 'g': g, 'public_key': elgamal_public_key, 'private_key': elgamal_private_key}
    }

    # Notify client with ElGamal key details
    emit('elgamal_keys', {
        'p': p,
        'g': g,
        'public_key': elgamal_public_key
    }, room=user_id)

    # Update user list for everyone
    emit('user_list', [user['username'] for user in connected_users.values()], broadcast=True)

@socketio.on('send_message')
def send_message(data):
    sender = connected_users[request.sid]
    recipient_name = data['recipient']
    message = data['message']
    encryption_method = data['encryption_method']

    # Find recipient
    recipient_id, recipient_keys = None, None
    for sid, user in connected_users.items():
        if user['username'] == recipient_name:
            recipient_id, recipient_keys = sid, user
            break

    if recipient_id and recipient_keys:
        if encryption_method == 'RSA':
            encrypted_message = encrypt_rsa(message, recipient_keys['rsa_keys']['public_key']).hex()
        elif encryption_method == 'ElGamal':
            encrypted_message = str(elgamal_encrypt(message, recipient_keys['elgamal_keys']['p'], recipient_keys['elgamal_keys']['g'], recipient_keys['elgamal_keys']['public_key']))
        else:
            return

        # Notify sender of encryption details
        emit('message_sent', {
            'recipient': recipient_name,
            'encrypted_message': encrypted_message,
            'encryption_method': encryption_method
        }, room=request.sid)

        # Send encrypted message to recipient
        emit('receive_message', {
            'sender': sender['username'],
            'encrypted_message': encrypted_message,
            'encryption_method': encryption_method
        }, room=recipient_id)

@socketio.on('decrypt_message')
def decrypt_message(data):
    user = connected_users[request.sid]
    encrypted_message = data['message']
    encryption_method = data['encryption_method']

    if encryption_method == 'RSA':
        decrypted_message = decrypt_rsa(bytes.fromhex(encrypted_message), user['rsa_keys']['private_key'])
    elif encryption_method == 'ElGamal':
        decrypted_message = elgamal_decrypt(eval(encrypted_message), user['elgamal_keys']['p'], user['elgamal_keys']['private_key'])
    else:
        decrypted_message = "Méthode non supportée."

    emit('decrypted_message', {'message': decrypted_message}, room=request.sid)

@socketio.on('disconnect')
def disconnect():
    user_id = request.sid
    if user_id in connected_users:
        del connected_users[user_id]
        emit('user_list', [user['username'] for user in connected_users.values()], broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
