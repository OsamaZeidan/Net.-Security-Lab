# server_ssl.py
import socket
import ssl
import threading
import random
import time
from datetime import datetime


# Logging
def log_event(event):
    with open("log.txt", "a") as f:
        f.write(f"[{datetime.now()}] {event}\n")


def handle_client(client_socket, address):
    print(f"[+] Client connected from {address}")
    log_event(f"Client connected from {address}")

    try:
        while True:
            menu = "\n--- MENU ---\n1. Start a new guessing game\n2. Exit\nChoose an option: "
            client_socket.send(menu.encode())

            choice_data = client_socket.recv(1024)
            if not choice_data:
                break
            choice = choice_data.decode().strip()
            log_event(f"{address} selected option: {choice}")

            if choice == "1":
                number = random.randint(1, 100)
                client_socket.send(b"Guess the number (1-100): ")

                while True:
                    guess_data = client_socket.recv(1024)
                    if not guess_data:
                        break

                    try:
                        guess = int(guess_data.decode().strip())
                        log_event(f"{address} guessed: {guess}")
                    except ValueError:
                        client_socket.send(b"Invalid input. Enter a number.\n")
                        continue

                    if guess < number:
                        client_socket.send(b"Higher\n")
                    elif guess > number:
                        client_socket.send(b"Lower\n")
                    else:
                        client_socket.send(b"Correct! You won!\n")
                        time.sleep(0.2)
                        break

                client_socket.send(b"\nReturning to main menu...\n")
                time.sleep(0.2)

            elif choice == "2":
                client_socket.send(b"Goodbye!\n")
                break
            else:
                client_socket.send(b"Invalid option.\n")

    except Exception as e:
        log_event(f"Error with {address}: {e}")
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
        except:
            pass
        log_event(f"Disconnected from {address}")
        print(f"[+] Disconnected from {address}")


def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)
    print("[+] SSL Server listening on port 12345")

    while True:
        client_sock, addr = server.accept()
        ssl_client_sock = context.wrap_socket(client_sock, server_side=True)
        thread = threading.Thread(target=handle_client, args=(ssl_client_sock, addr))
        thread.start()


if __name__ == "__main__":
    start_server()
