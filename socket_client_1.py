from encryption import ecb_encrypt, ecb_decrypt
from rsa import encrypt_rsa
import socket
import random
import threading

def listen_to_server(client_socket, des_key):
    while True:
        try:
            encrypted_data = client_socket.recv(1024)
            if not encrypted_data:
                print("Disconnected from server.")
                break

            decrypted_message = ecb_decrypt(encrypted_data.decode(), des_key)
            print(f"Server: {decrypted_message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))

    server_public_key = eval(client_socket.recv(1024).decode())
    print(f"Server Public Key: {server_public_key}")

    des_key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
    print(f"Generated DES key: {des_key}")

    encrypted_key = encrypt_rsa(server_public_key, des_key)
    client_socket.send(str(encrypted_key).encode())

    listening_thread = threading.Thread(target=listen_to_server, args=(client_socket, des_key))
    listening_thread.daemon = True
    listening_thread.start()

    while True:
        try:
            message = input("Enter message (type 'exit' to quit): ")
            if message.lower() == "exit":
                break

            encrypted_message = ecb_encrypt(message, des_key)
            client_socket.send(encrypted_message.encode())
        except Exception as e:
            print(f"Error sending message: {e}")
            break

    client_socket.close()

if __name__ == '__main__':
    main()
