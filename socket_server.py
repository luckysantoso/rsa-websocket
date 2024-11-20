from encryption import ecb_encrypt, ecb_decrypt
from rsa import generate_keypair, encrypt_rsa, decrypt_rsa
import socket
import threading

clients = {}  # Menyimpan client dan kunci DES mereka

def handle_client(conn, address, private_key, public_key):
    client_id = f"{address[0]}:{address[1]}"
    print(f"Connection from: {client_id}")

    try:
        # Kirim public key RSA ke client
        conn.send(str(public_key).encode())

        # Terima encrypted DES key
        encrypted_key = eval(conn.recv(1024).decode())
        des_key = decrypt_rsa(private_key, encrypted_key)
        clients[client_id] = {'conn': conn, 'key': des_key}
        print(f"Received DES key from {client_id}: {des_key}")

        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            # Dekripsi pesan dengan kunci DES client pengirim
            decrypt_msg = ecb_decrypt(data, des_key)
            print(f"From {client_id}: {decrypt_msg}")

            # Parsing target pesan
            if decrypt_msg.startswith("@"):
                target_id, message = decrypt_msg[1:].split(" ", 1)
                if target_id in clients:
                    target_conn = clients[target_id]['conn']
                    target_key = clients[target_id]['key']
                    encrypted_msg = ecb_encrypt(f"[{client_id}] {message}", target_key)
                    target_conn.send(encrypted_msg.encode())
                else:
                    error_msg = f"Client {target_id} tidak ditemukan."
                    conn.send(ecb_encrypt(error_msg, des_key).encode())
            else:
                error_msg = "Format pesan tidak valid. Gunakan format '@client_id pesan'."
                conn.send(ecb_encrypt(error_msg, des_key).encode())

    except Exception as e:
        print(f"Error with {client_id}: {e}")

    finally:
        conn.close()
        del clients[client_id]
        print(f"Connection closed: {client_id}")

if __name__ == '__main__':
    public_key, private_key = generate_keypair()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(5)
    print("Server listening...")

    while True:
        conn, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, address, private_key, public_key)).start()
