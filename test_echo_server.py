#!/usr/bin/env python3
import socket
import threading
import sys

def handle_client(client_socket, addr):
    try:
        data = client_socket.recv(1024)
        if data:
            client_socket.send(data)
    except:
        pass
    finally:
        client_socket.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(100)
    print(f"Echo server listening on 127.0.0.1:{port}")
    
    try:
        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("Server stopped")
    finally:
        server.close()

if __name__ == "__main__":
    main()