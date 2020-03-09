import sys
from Transport import Transport


class Client:
    def __init__(self):
        if len(sys.argv) < 2:
            self.host = input("Enter host ip address: ")
            self.s = Transport()
        else:
            self.host = sys.argv[1]

    def banner(self):
        pass

    def display(self):
        you = "\33[33m\33[1m> \33[0m"
        sys.stdout.write(you)
        sys.stdout.flush()


if __name__ == '__main__':
    c = Client()
    c.s.connect(c.host, 12000)
    while True:
        c.display()
        data = c.s.communicate()
        if data != "SENT":
            print("@Peer: " + data.decode().strip())

