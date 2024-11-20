from encryption import ecb_encrypt, ecb_decrypt
from rsa import encrypt_rsa
import socket
import random

if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))

    # Terima public key server
    server_public_key = eval(client_socket.recv(1024).decode())
    print(f"Server Public Key: {server_public_key}")

    # Generate random DES key
    des_key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
    print(f"Generated DES key: {des_key}")

    # Enkripsi DES key dengan RSA
    encrypted_key = encrypt_rsa(server_public_key, des_key)
    client_socket.send(str(encrypted_key).encode())

    while True:
        message = input("Enter message (type 'exit' to quit): ")
        if message.lower() == "exit":
            break

        # Format: @client_id pesan
        encrypt_msg = ecb_encrypt(message, des_key)
        client_socket.send(encrypt_msg.encode())

        # Terima pesan balasan
        data = client_socket.recv(1024).decode()
        decrypt_msg = ecb_decrypt(data, des_key)
        print(f"Client: {decrypt_msg}")

    client_socket.close()
