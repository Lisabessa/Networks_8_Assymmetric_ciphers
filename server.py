import socket
import os
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

HOST = 'localhost'
PORT = 8080
KEY_FILE = "server_private_key.pem"
PUB_KEY_FILE = "server_public_key.pem"

def generate_keys():
    # Генерация или загрузка ключей
    if not os.path.exists(KEY_FILE):
        key = RSA.generate(2048)
        with open(KEY_FILE, 'wb') as f:
            f.write(key.export_key())
        with open(PUB_KEY_FILE, 'wb') as f:
            f.write(key.publickey().export_key())
    else:
        with open(KEY_FILE, 'rb') as f:
            key = RSA.import_key(f.read())
        with open(PUB_KEY_FILE, 'rb') as f:
            public_key = RSA.import_key(f.read())
    private_key = key
    public_key = key.publickey()
    return (private_key, public_key)


def run_server(keys):
    private_key, public_key = keys = keys
    with socket.socket() as sock:
        sock.bind((HOST, PORT))
        sock.listen(1)
        print(f"Сервер запущен на {HOST}:{PORT}")

        conn, addr = sock.accept()
        print(f"Клиент подключился: {addr}")

        # Прием открытого ключа клиента
        client_public_key_data = conn.recv(4096)
        client_public_key = RSA.import_key(client_public_key_data)

        # Отправка своего открытого ключа клиенту
        conn.send(public_key.export_key())

        # Бесконечный цикл приема сообщений
        while True:
            # Прием зашифрованного сообщения от клиента
            encrypted_msg = conn.recv(4096)
            if not encrypted_msg:
                print("Клиент отключился")
                break

            # Расшифровка сообщения
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_msg = cipher_rsa.decrypt(encrypted_msg)
            print(f"Получено зашифрованное сообщение: {decrypted_msg.decode()}")

            # Ответ клиенту
            response = "Сообщение успешно получено!"
            cipher_rsa = PKCS1_OAEP.new(client_public_key)
            encrypted_response = cipher_rsa.encrypt(response.encode())
            conn.send(encrypted_response)
        print("Завершение работы сервера.")


run_server(generate_keys())