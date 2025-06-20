import streamlit as st
import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest

# --- PAGE CONFIG ---
st.set_page_config(page_title="SmartShield IDS", layout="centered")

# --- AUTHENTICATION ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.subheader("🔐 Admin Login Required")
    password = st.text_input("Enter admin password:", type="password")
    if password == "smartshield2025":
        st.session_state.authenticated = True
        st.success("✅ Access granted! Scroll down to continue.")
    else:
        st.warning("Waiting for correct password...")
        st.stop()

# --- TITLE ---
st.title("🔐 SmartShield – Intrusion Detection System")
st.write("Upload a network log CSV file to detect suspicious activity using AI.")

# --- FILE UPLOADER ---
uploaded_file = st.file_uploader("📤 Upload CSV File", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    st.subheader("📄 Uploaded Data")
    st.dataframe(df)

    # --- ANOMALY DETECTION ---
    with st.spinner("Analyzing with AI..."):
        model = IsolationForest(contamination=0.2, random_state=42)
        model.fit(df.select_dtypes(include=np.number))
        df['anomaly'] = model.predict(df.select_dtypes(include=np.number))
        df['anomaly_label'] = df['anomaly'].map({1: "✅ Normal", -1: "⚠️ Suspicious"})

    st.subheader("📊 Detection Results")
    st.dataframe(df)

    st.subheader("⚠️ Suspicious Entries")
    st.dataframe(df[df['anomaly_label'] == "⚠️ Suspicious"])

    # --- GRAPHS ---
    st.subheader("📈 Suspicion Score Over Time")
    df['suspicion_score'] = df['bytes_sent'] + df['bytes_received']
    df['log_index'] = df.index

    fig1, ax1 = plt.subplots()
    ax1.plot(df['log_index'], df['suspicion_score'], color='orange')
    ax1.set_xlabel("Log Entry Index")
    ax1.set_ylabel("Suspicion Score")
    ax1.set_title("Suspicion Score Trend")
    st.pyplot(fig1)

    st.subheader("📊 Anomalies by User")
    fig2, ax2 = plt.subplots(figsize=(12, 5))
    sns.countplot(data=df[df['anomaly_label'] == "⚠️ Suspicious"], x='username', ax=ax2)
    ax2.set_title("Suspicious Activity Count per User")
    ax2.set_xlabel("Username")
    ax2.set_ylabel("Suspicious Records")
    plt.xticks(rotation=45, ha='right')
    st.pyplot(fig2)


    st.subheader("📊 Normal vs Suspicious Entries")
    labels = ['Normal', 'Suspicious']
    sizes = [
        len(df[df['anomaly_label'] == "✅ Normal"]),
        len(df[df['anomaly_label'] == "⚠️ Suspicious"])
    ]
    fig3, ax3 = plt.subplots()
    ax3.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['green', 'red'])
    ax3.set_title("Anomaly Distribution")
    st.pyplot(fig3)

    # --- LIVE SIMULATION ---
    st.subheader("📡 Live Detection Simulation")
    for i in range(min(20, len(df))):
        log = df.iloc[i]
        label = log['anomaly_label']
        st.write(f"👤 {log.get('username', 'Unknown')} | 📟 {log['login_time']} | {label}")
        time.sleep(0.15)

    # --- DOWNLOADABLE REPORT ---
    st.subheader("📥 Download Anomaly Report")
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("Download CSV", csv, "anomaly_report.csv", "text/csv")

    # --- STATS PANEL ---
    st.subheader("📊 Stats Overview")
    total = len(df)
    anomalies = len(df[df['anomaly_label'] == "⚠️ Suspicious"])
    normal = total - anomalies
    st.metric("🔍 Total Records", total)
    st.metric("⚠️ Anomalies Detected", anomalies)
    st.metric("✅ Normal Entries", normal)

else:
    st.info("Please upload a CSV file with numeric fields like: duration, bytes_sent, bytes_received, login_time, etc.")
