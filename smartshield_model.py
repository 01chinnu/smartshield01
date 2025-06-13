import pandas as pd
from sklearn.ensemble import IsolationForest

# Load data
df = pd.read_csv("network_logs.csv")

# Train model
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(df)

# Predict
df['anomaly'] = model.predict(df)
df['anomaly_label'] = df['anomaly'].map({1: "✅ Normal", -1: "⚠️ Suspicious"})

# Show results
print("\n--- Detection Results ---\n")
print(df[['duration', 'bytes_sent', 'bytes_received', 'login_time', 'anomaly_label']])
