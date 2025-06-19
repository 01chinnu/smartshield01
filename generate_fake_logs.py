import pandas as pd
import random
from datetime import datetime, timedelta

NUM_RECORDS = 200
SUSPICIOUS_RATIO = 0.15
users = ['alice', 'bob', 'charan', 'deepa', 'faculty1', 'student12', 'admin', 'rajesh', 'guest']
rows = []
base_time = datetime(2025, 6, 19, 9, 0, 0)

for i in range(NUM_RECORDS):
    user = random.choice(users)
    login_time = base_time + timedelta(minutes=random.randint(0, 1440))
    duration = random.randint(30, 600)
    bytes_sent = random.randint(1_000, 50_000)
    bytes_received = random.randint(1_000, 100_000)

    if random.random() < SUSPICIOUS_RATIO:
        if random.random() < 0.5:
            duration = random.randint(5, 30)
            bytes_sent *= 3
            bytes_received *= 2
        else:
            duration = random.randint(300, 1800)
            bytes_sent *= random.randint(5, 10)
            user = "suspicious_" + user

    rows.append({
        "username": user,
        "login_time": login_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration": duration,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received
    })

pd.DataFrame(rows).to_csv("demo_network_logs.csv", index=False)
print("✅ Fake demo log file saved as 'demo_network_logs.csv'")

