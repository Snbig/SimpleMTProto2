from socket import *
import select


class Server:
    def __init__(self, port):
        self.port = port
        ssocket = socket(AF_INET, SOCK_STREAM)
        ssocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        ssocket.bind(('', self.port))
        ssocket.listen(2)
        print(f"[@] Server started on port {self.port}")
        self.secret_chat = 0
        self.client_sockets = [ssocket]
        self.get_connection()

    def get_connection(self):
        while True:
            rList, wList, error_sockets = select.select(self.client_sockets, [], [])
            for sock in rList:
                if sock == self.client_sockets[0]:
                    csock, address = self.client_sockets[0].accept()
                    self.client_sockets.append(csock)
                    print(f"Got connection from {csock.getpeername()}")
                else:
                    self.new_chat(sock)

    def new_chat(self, sock):
        data = sock.recv(2048)
        if data[:12] == b"STARTSECCHAT":
            for c in self.client_sockets[1:]:
                if c.getpeername() == sock.getpeername():
                    continue
                c.send(b"STARTSECCHATREQ")
                res = c.recv(16).decode()
                if res[:15] == "STARTSECCHATACK":
                    sock.send(b"STARTSECCHATACK")
                elif res == "STARTSECCHATNACK":
                    sock.send(b"STARTSECCHATNACK")
        elif data[:4] == b"SEEN":
            sock.send(b"SEEN")
        else:
            print(f"Data from {sock.getpeername()}: {data}")
            for c in self.client_sockets[1:]:
                if c.getpeername() == sock.getpeername():
                    continue
                if self.secret_chat >= 2:
                    c.send(data)
                    if self.isseen(c):
                        sock.send(b"SEEN")
                elif data[:8].decode() == "DHPARAMS":
                    print(f"\n[+] DH parameters:{data}\n")
                    c.send(data)
                elif data[:10].decode() == "PPUBLICKEY":
                    print(f"\n[x] Peer public key: {data}\n")
                    self.secret_chat += 1
                    c.send(data)
                else:
                    c.send(data)
                    if self.isseen(c):
                        sock.send(b"SEEN")

    def isseen(self, c):
        state = c.recv(4).decode()
        if state == "SEEN":
            return True


if __name__ == '__main__':
    s = Server(12000)
