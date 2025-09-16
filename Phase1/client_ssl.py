# client_ssl.py
import socket
import ssl


def main():
    host = input("Enter server IP (e.g., 127.0.0.1): ")
    port = 12345

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed cert

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = context.wrap_socket(raw_sock, server_hostname=host)
        client.connect((host, port))
        print("[+] Secure SSL connection established.\n")

        while True:
            menu = client.recv(1024).decode()
            print(menu, end="")
            option = input()
            client.send(option.encode())

            if option.strip() == "1":
                while True:
                    prompt = client.recv(1024).decode()
                    print(prompt, end="")
                    if "Correct!" in prompt or "won" in prompt.lower():
                        extra = client.recv(1024).decode()
                        print(extra, end="")
                        break
                    guess = input()
                    client.send(guess.encode())

            elif option.strip() == "2":
                print(client.recv(1024).decode())
                break
            else:
                print(client.recv(1024).decode())

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        try:
            client.close()
            print("[+] Connection closed.")
        except:
            print("[-] Socket already closed.")


if __name__ == "__main__":
    main()
