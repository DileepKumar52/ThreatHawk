import random
from datetime import datetime, timedelta

failed_ips = [
    "192.168.1.10",
    "45.227.255.206",
    "103.88.12.45",
    "185.143.223.11"
]

normal_ips = [
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.22",
    "8.8.8.8",
    "1.1.1.1"
]

ports = [22, 80, 443, 8080, 3306]

start = datetime(2026, 7, 6, 10, 0, 0)

with open("big_ssh_logs.txt", "w") as f:
    for i in range(500):
        timestamp = start + timedelta(seconds=i)

        event_type = random.randint(1, 100)

        if event_type <= 45:
            ip = random.choice(failed_ips)
            line = f"{timestamp} Failed login from {ip}"

        elif event_type <= 70:
            ip = random.choice(normal_ips)
            line = f"{timestamp} Successful login from {ip}"

        else:
            ip = random.choice(normal_ips + failed_ips)
            port = random.choice(ports)
            line = f"{timestamp} Connection attempt from {ip} to port {port}"

        f.write(line + "\n")

print("Generated big_ssh_logs.txt")