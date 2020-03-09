from socket import *
import select
import sys
from DH import DH
from Oracle import Oracle


class Transport:
    def __init__(self):
        self.uri = None
        self.socket = None
        self.shared_secret = None
        self.pre_dh_state = 0
        self.dh = None
        self.secret_chat = 0
        self.o = None
        self.org = None

    def connect(self, ip, port):
        self.uri = (ip, port)
        csocket = socket(AF_INET, SOCK_STREAM)
        try:
            csocket.connect(self.uri)
            self.socket = csocket
            return True
        except:
            return False

    def isseen(self):
        state = self.socket.recv(4).decode()
        if state == "SEEN":
            return True

    def start_secret_chat(self):
        self.socket.send(b"STARTSECCHAT")
        data = self.socket.recv(15).decode()
        if data == "STARTSECCHATACK":
            return True
        exit("Peer refused chat or timeout reached!")

    def send(self, message):
        self.socket.send(message)
        if self.isseen():
            return True
        return True

    def pre_key_generation(self):
        if self.pre_dh_state == 0:
            sys.stdout.write("Pre Key Generation Started. Please Wait...\n")
            self.dh = DH()
            self.pre_dh_state = 1
            sys.stdout.write("Pre Key Generation Completed.\n")
            self.display()

    def communicate(self):
        self.pre_key_generation()
        while True:
            rList, wList, error_sockets = select.select([self.socket, sys.stdin], [], [])
            for sock in rList:
                if sock == self.socket:
                    data = sock.recv(1024)
                    if self.secret_chat == 1 and data[:4] != b"SEEN" and data[:15] != b"STARTSECCHATREQ":
                        msg_key = data[:16]
                        d_msg = self.o.decrypt(data, msg_key, self.org)
                        sock.send(b"SEEN")
                        return d_msg
                    if data[:15] == b"STARTSECCHATREQ" and self.secret_chat == 0:
                        answer = input("New secret chat request. Do you want to accept? (Y/n): ")
                        if answer.lower() == "y" or answer.lower() == '':
                            self.org = "op"
                            self.socket.send(b"STARTSECCHATACK")
                        else:
                            self.socket.send(b"STARTSECCHATNACK")
                            sys.stdout.write("Peer refused secret chat connection!\n")
                            self.display()
                    elif data[:16] == b"STARTSECCHATNACK":
                        sys.stdout.write("Peer refused secret chat connection!\n")
                        self.display()
                    elif data[:15] == b"STARTSECCHATACK":
                        self.org = "org"
                        self.dh.gen_private()
                        self.socket.send(b"DHPARAMS" + self.dh.dh_parameters)
                    elif data[:8] == b"DHPARAMS":
                        self.dh.dh_parameters = data[8:]
                        self.dh.gen_private()
                        self.dh.gen_public()
                        self.socket.send(b"PPUBLICKEY" + self.dh.public_key)
                    elif data[:10] == b"PPUBLICKEY":
                        peer_pub_key = data[10:]
                        self.shared_secret = self.dh.gen_shared_key(peer_pub_key)
                        self.o = Oracle(self.shared_secret)
                        self.secret_chat = 1
                        sys.stdout.write("Secret shared key generated\n")
                        self.display()
                        sys.stdout.write("~~~ [+] Secret chat started [+] ~~~\n")
                        self.display()
                        if self.dh.public_key is None:
                            self.dh.gen_public()
                            self.socket.send(b"PPUBLICKEY" + self.dh.public_key)
                    elif data[:4] == b"SEEN":
                        sys.stdout.write("[*] Seen\n")
                        self.display()
                    else:
                        sock.send(b"SEEN")
                        return data
                else:
                    msg = sys.stdin.readline()
                    if msg.strip() == "/help":
                        sys.stdout.write("/help : Help  /secret : Starting secret chat\n")
                        self.display()
                    elif msg.strip() == "/secret":
                        if self.secret_chat == 0:
                            self.socket.send(b"STARTSECCHATREQ")
                            return "SENT"
                        else:
                            return b"Secret chat already established."

                    elif self.secret_chat == 1 and self.shared_secret is not None:
                        e_msg = self.o.encrypt(msg.encode(), self.org)
                        if self.socket.send(e_msg):
                            return "SENT"
                    elif self.socket.send(msg.encode()) and msg != '':
                        return "SENT"

    def display(self):
        you = "\33[33m\33[1m> \33[0m"
        sys.stdout.write(you)
        sys.stdout.flush()
