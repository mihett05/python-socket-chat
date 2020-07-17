import socket
import threading

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 6780))
sock.setblocking(False)


def read_input_thread():
    while True:
        msg = input()
        if msg:
            sock.sendall(msg.encode("utf-8"))


t = threading.Thread(target=read_input_thread, args=())
t.start()
print("Commands:\nlogin your_login your_password\nregister your_login your_password")
while True:
    try:
        data = sock.recv(1024).decode("utf-8")
        if data == "":
            break
        print(data)
    except BlockingIOError:
        pass


sock.close()
