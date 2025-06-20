import streamlit as st
import pandas as pd
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
import streamlit_authenticator as stauth
import yaml
import json
import os
from yaml.loader import SafeLoader

# --- PAGE CONFIG ---
st.set_page_config(page_title="SmartShield IDS", layout="centered")

# --- USER REGISTRATION ---
def register_user():
    st.subheader("📝 Sign Up")
    new_name = st.text_input("Full Name")
    new_username = st.text_input("Choose a Username")
    new_email = st.text_input("Email")
    new_password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if new_password != confirm:
            st.error("❌ Passwords do not match")
        elif not new_username or not new_password or not new_name or not new_email:
            st.error("❌ All fields are required")
        else:
            if os.path.exists("users.json"):
                with open("users.json", "r") as f:
                    users = json.load(f)
            else:
                users = {}

            if new_username in users:
                st.error("❌ Username already exists")
            else:
                hashed_pw = stauth.Hasher([new_password]).generate()[0]
                users[new_username] = {
                    "email": new_email,
                    "name": new_name,
                    "password": hashed_pw
                }
                with open("users.json", "w") as f:
                    json.dump(users, f, indent=2)
                st.success("✅ User registered successfully! You can now log in.")

# --- SIGN UP TOGGLE ---
if "signup_mode" not in st.session_state:
    st.session_state.signup_mode = False

if st.sidebar.button("🔄 Toggle Sign Up / Login"):
    st.session_state.signup_mode = not st.session_state.signup_mode

# --- SIGNUP MODE ---
if st.session_state.signup_mode:
    register_user()
    st.stop()

# --- USER LOGIN ---
if os.path.exists("users.json"):
    with open("users.json", "r") as f:
        user_data = json.load(f)
else:
    user_data = {}

dynamic_credentials = {"usernames": {}}
for uname, uinfo in user_data.items():
    dynamic_credentials["usernames"][uname] = {
        "email": uinfo["email"],
        "name": uinfo["name"],
        "password": uinfo["password"]
    }

config = {
    "credentials": dynamic_credentials,
    "cookie": {"name": "smartshield_cookie", "key": "some_secure_key", "expiry_days": 30}
}

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"]
)

name, authentication_status, username = authenticator.login("Login", "main")

if authentication_status:
    st.success(f"Welcome {name} 👋")
    authenticator.logout("Logout", "sidebar")

    st.title("🔐 SmartShield – Intrusion Detection System")
    st.write("Upload a network log CSV file to detect suspicious activity using AI.")

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

        # --- CONDITIONAL VISUALS ---
        st.markdown("---")
        st.subheader("📊 Visualizations")

        if st.checkbox("📈 Show Suspicion Score Over Time"):
            df['suspicion_score'] = df['bytes_sent'] + df['bytes_received']
            df['log_index'] = df.index
            fig1, ax1 = plt.subplots()
            ax1.plot(df['log_index'], df['suspicion_score'], color='orange')
            ax1.set_xlabel("Log Entry Index")
            ax1.set_ylabel("Suspicion Score")
            ax1.set_title("Suspicion Score Trend")
            st.pyplot(fig1)

        if st.checkbox("📊 Show Anomalies by User"):
            fig2, ax2 = plt.subplots(figsize=(12, 5))
            sns.countplot(data=df[df['anomaly_label'] == "⚠️ Suspicious"], x='username', ax=ax2)
            ax2.set_title("Suspicious Activity Count per User")
            ax2.set_xlabel("Username")
            ax2.set_ylabel("Suspicious Records")
            plt.xticks(rotation=45, ha='right')
            st.pyplot(fig2)

        if st.checkbox("🥧 Show Normal vs Suspicious Distribution"):
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
        st.info("Please upload a CSV file.")

elif authentication_status is False:
    st.error("❌ Incorrect username or password")

elif authentication_status is None:
    st.warning("Please enter your credentials")
