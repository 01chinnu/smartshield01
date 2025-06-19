import streamlit as st
import pandas as pd
import numpy as np
import cv2
import time
from sklearn.ensemble import IsolationForest

# --- PAGE CONFIG ---
st.set_page_config(page_title="SmartShield IDS", layout="centered")

# --- AUTHENTICATION ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    password = st.text_input("🔐 Enter admin password:", type="password")
    login_btn = st.button("Login")

    if login_btn:
        if password == "smartshield2025":
            st.session_state.authenticated = True
            st.success("✅ Access granted!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password")
    st.stop()


# --- TITLE ---
st.title("\U0001f512 SmartShield – Intrusion Detection System")
st.write("Upload a network log CSV file to detect suspicious activity using AI.")

# --- FILE UPLOADER ---
uploaded_file = st.file_uploader("\U0001f4e4 Upload CSV File", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    st.subheader("\U0001f4c4 Uploaded Data")
    st.dataframe(df)

    # --- ANOMALY DETECTION ---
    with st.spinner("Analyzing with AI..."):
        model = IsolationForest(contamination=0.2, random_state=42)
        model.fit(df.select_dtypes(include=np.number))
        df['anomaly'] = model.predict(df.select_dtypes(include=np.number))
        df['anomaly_label'] = df['anomaly'].map({1: "\u2705 Normal", -1: "\u26a0\ufe0f Suspicious"})

    st.subheader("\U0001f4ca Detection Results")
    st.dataframe(df)

    st.subheader("\u26a0\ufe0f Suspicious Entries")
    st.dataframe(df[df['anomaly_label'] == "\u26a0\ufe0f Suspicious"])

    # --- HEATMAP ---
    st.subheader("\U0001f525 Suspicion Heatmap")
    df["suspicion_score"] = df["bytes_sent"] + df["bytes_received"]
    norm_scores = (df["suspicion_score"] - df["suspicion_score"].min()) / (df["suspicion_score"].max() - df["suspicion_score"].min())
    norm_scores = (norm_scores * 255).astype(np.uint8)
    heatmap_input = np.expand_dims(norm_scores.values, axis=0)
    heatmap = cv2.applyColorMap(heatmap_input, cv2.COLORMAP_JET)
    st.image(heatmap, channels="BGR", caption="Intensity = potential risk")

    # --- LIVE SIMULATION ---
    st.subheader("\U0001f4e1 Live Detection Simulation")
    for i in range(min(20, len(df))):
        log = df.iloc[i]
        label = log['anomaly_label']
        st.write(f"\U0001f464 {log.get('username', 'Unknown')} | ⏰ {log['login_time']} | {label}")
        time.sleep(0.15)

    # --- DOWNLOADABLE REPORT ---
    st.subheader("\U0001f4e5 Download Anomaly Report")
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("Download CSV", csv, "anomaly_report.csv", "text/csv")

    # --- STATS PANEL ---
    st.subheader("\U0001f4c8 Stats Overview")
    total = len(df)
    anomalies = len(df[df['anomaly_label'] == "\u26a0\ufe0f Suspicious"])
    normal = total - anomalies
    st.metric("\U0001f50d Total Records", total)
    st.metric("\u26a0\ufe0f Anomalies Detected", anomalies)
    st.metric("\u2705 Normal Entries", normal)

else:
    st.info("Please upload a CSV file with numeric fields like: duration, bytes_sent, bytes_received, login_time, etc.")
