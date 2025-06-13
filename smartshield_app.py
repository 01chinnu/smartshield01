import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="SmartShield IDS", layout="centered")

st.title("🔐 SmartShield – Intrusion Detection System")
st.write("Upload a network log CSV file to detect suspicious activity using AI.")

uploaded_file = st.file_uploader("📤 Upload CSV File", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.subheader("📄 Uploaded Data")
    st.dataframe(df)

    with st.spinner("Analyzing..."):
        model = IsolationForest(contamination=0.2, random_state=42)
        model.fit(df)
        df['anomaly'] = model.predict(df)
        df['anomaly_label'] = df['anomaly'].map({1: "✅ Normal", -1: "⚠️ Suspicious"})

    st.subheader("📊 Detection Results")
    st.dataframe(df)

    st.subheader("⚠️ Suspicious Entries")
    st.dataframe(df[df['anomaly_label'] == "⚠️ Suspicious"])

else:
    st.info("Please upload a CSV file with columns like: duration, bytes_sent, bytes_received, login_time.")
