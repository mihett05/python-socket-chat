import socket
import sqlite3
import hashlib
import os
import datetime


class Server:
    def __init__(self, host="", port=6780):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(1)
        self.socket.setblocking(False)

        self.db = sqlite3.connect("db.sqlite3")
        self.cur = self.db.cursor()

        self.clients = dict()
        self.logged = dict()
        self.nicks = dict()

        self.queue = []
        self.direct_queue = []

        self.disconnected = []

    def broadcast(self, msg):
        if len(msg) > 0:
            self.queue.append(msg)

    def direct(self, addr, msg):
        if addr in self.clients and len(msg) > 0:
            self.direct_queue.append((addr, msg))

    def connected(self, conn, addr):
        self.clients[addr] = conn

    def received(self, addr, data):
        if addr in self.logged and addr in self.nicks:
            self.broadcast(f"[{self.nicks[addr]}]: " + data)
        else:
            cmd = data.split()
            if len(cmd) == 3:
                if cmd[0] == "login":
                    self.login(addr, cmd[1], cmd[2])
                elif cmd[0] == "register":
                    self.register(addr, cmd[1], cmd[2])

    def login(self, addr, login, password):
        user = self.cur.execute("SELECT id, login, password, salt, last_joined FROM users WHERE login = ?",
                                [login]).fetchone()
        if user:
            user_id, user_login, user_password, salt, last_joined = user
            key = hashlib.pbkdf2_hmac(
                "sha512",
                password.encode("utf-8"),
                salt,
                100000,
                dklen=128
            )
            if key == user_password:
                already_addr = None
                for k, v in self.nicks.items():
                    if v == user_login:
                        self.disconnected.append(k)
                        break

                self.logged[addr] = self.clients[addr]
                self.nicks[addr] = user_login

                self.cur.execute("""
                    UPDATE users
                    SET last_joined = ?
                    WHERE id = ?
                """, [str(datetime.datetime.now()), user_id])
                self.db.commit()

                self.direct(addr, "Successful login")
                self.broadcast(f"{self.nicks[addr]} connected")
            else:
                self.direct(addr, "Invalid login or password")
        else:
            self.direct(addr, "Invalid login or password")

    def register(self, addr, login, password):
        user = self.cur.execute("SELECT * FROM users WHERE login = ?", [login]).fetchone()
        if user:
            self.direct(addr, "Login already taken")
        else:
            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac(
                "sha512",
                password.encode("utf-8"),
                salt,
                100000,
                dklen=128
            )
            self.cur.execute("""
                INSERT INTO users(login, password, salt, last_joined, date_joined)
                VALUES (?, ?, ?, ?, ?)
            """, [login, key, salt, str(datetime.datetime.now()), str(datetime.datetime.now())])
            self.db.commit()
            self.direct(addr, "Successful registration")
            self.login(addr, login, password)

    def clear(self):
        self.cur.close()
        self.db.close()

    def run(self):
        # init
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
                login varchar(255) NOT NULL,
                password varchar(128) NOT NULL,
                salt varchar(32) NOT NULL,
                last_joined datetime NOT NULL,
                date_joined datetime NOT NULL
            )
        """)
        self.db.commit()

        while True:
            # accept
            try:
                conn, addr = self.socket.accept()
                self.connected(conn, addr)
            except BlockingIOError:
                pass

            # recv
            for addr in self.clients:
                client = self.clients[addr]
                data = []
                try:
                    while True:
                        buff = client.recv(8192).decode("utf-8")
                        if not buff:
                            break
                        data.append(buff)
                except BlockingIOError:
                    pass
                except ConnectionError:
                    self.disconnected.append(addr)
                if len(data) > 0:
                    self.received(addr, "".join(data))

            # send
            if len(self.queue) > 0:
                for addr in self.clients:
                    client = self.clients[addr]
                    try:
                        client.sendall("\n".join(self.queue).encode("utf-8"))
                    except BlockingIOError:
                        pass
                    except ConnectionError:
                        self.disconnected.append(addr)

            if len(self.direct_queue) > 0:
                for addr in set(map(lambda x: x[0], self.direct_queue)):
                    try:
                        data = "\n".join(map(lambda x: x[1], filter(lambda x: x[0] == addr, self.direct_queue)))
                        if data:
                            self.clients[addr].sendall(data.encode("utf-8"))
                    except BlockingIOError:
                        pass
                    except ConnectionError:
                        self.disconnected.append(addr)

            # clear
            self.queue.clear()
            self.direct_queue.clear()
            for addr in self.disconnected:
                if addr in self.clients:
                    self.clients.pop(addr)
                    if addr in self.logged and addr in self.nicks:
                        self.queue.append(f"{self.nicks[addr]} disconnected")
                        self.logged.pop(addr)
                        self.nicks.pop(addr)
            self.disconnected.clear()


s = Server()
s.run()
s.clear()
