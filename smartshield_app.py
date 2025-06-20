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
from datetime import datetime
from yaml.loader import SafeLoader

# --- CONFIG ---
st.set_page_config(page_title="SmartShield IDS", layout="wide")

# --- HISTORY SETUP ---
HISTORY_DIR = "history"
os.makedirs(HISTORY_DIR, exist_ok=True)

def save_to_history(df, title=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_id = title or f"log_{timestamp}"
    csv_path = os.path.join(HISTORY_DIR, f"{file_id}.csv")
    json_path = os.path.join(HISTORY_DIR, f"{file_id}.json")
    df.to_csv(csv_path, index=False)
    metadata = {
        "title": file_id,
        "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "record_count": len(df)
    }
    with open(json_path, "w") as f:
        json.dump(metadata, f, indent=2)

def list_saved_histories():
    items = []
    for file in os.listdir(HISTORY_DIR):
        if file.endswith(".json"):
            with open(os.path.join(HISTORY_DIR, file), "r") as f:
                metadata = json.load(f)
                items.append((file[:-5], metadata))
    return sorted(items, key=lambda x: x[1]["uploaded_at"], reverse=True)

def load_history_df(file_id):
    csv_path = os.path.join(HISTORY_DIR, f"{file_id}.csv")
    return pd.read_csv(csv_path)

def delete_history_item(file_id):
    os.remove(os.path.join(HISTORY_DIR, f"{file_id}.csv"))
    os.remove(os.path.join(HISTORY_DIR, f"{file_id}.json"))

def clear_history():
    for file in os.listdir(HISTORY_DIR):
        os.remove(os.path.join(HISTORY_DIR, file))

# --- SIGNUP ---
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
        elif not new_username or not new_password or not new_email or not new_name:
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
                st.success("✅ Registration successful. You can now log in.")

# --- SIGNUP TOGGLE ---
if "signup_mode" not in st.session_state:
    st.session_state.signup_mode = False

if st.sidebar.button("🔄 Toggle Sign Up / Login"):
    st.session_state.signup_mode = not st.session_state.signup_mode

if st.session_state.signup_mode:
    register_user()
    st.stop()

# --- LOGIN SETUP ---
if os.path.exists("users.json"):
    with open("users.json", "r") as f:
        user_data = json.load(f)
else:
    user_data = {}

dynamic_credentials = {"usernames": {}}
for uname, info in user_data.items():
    dynamic_credentials["usernames"][uname] = {
        "email": info["email"],
        "name": info["name"],
        "password": info["password"]
    }

config = {
    "credentials": dynamic_credentials,
    "cookie": {"name": "smartshield_cookie", "key": "somekey", "expiry_days": 30}
}

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"]
)

st.subheader("🔐 Login to SmartShield")
name, authentication_status, username = authenticator.login(location="main")

if authentication_status:
    st.success(f"Welcome {name} 👋")
    authenticator.logout("Logout", "sidebar")
elif authentication_status is False:
    st.error("Incorrect username or password")
elif authentication_status is None:
    st.warning("Please enter your credentials")


# --- MAIN APP ---
if authentication_status:
    st.sidebar.markdown(f"👋 Welcome **{name}**")
    authenticator.logout("Logout", "sidebar")

    st.title("🔐 SmartShield – Intrusion Detection System")

    # Sidebar: History
    st.sidebar.markdown("### 🕓 History")
    history = list_saved_histories()
    selected_log = None

    for file_id, meta in history:
        col1, col2 = st.sidebar.columns([0.85, 0.15])
        if col1.button(meta["title"], key=file_id):
            selected_log = file_id
        if col2.button("⋮", key=file_id + "_opt"):
            if st.sidebar.button(f"Delete {meta['title']}", key=file_id + "_del"):
                delete_history_item(file_id)
                st.experimental_rerun()

    if history and st.sidebar.button("🗑️ Clear History"):
        clear_history()
        st.experimental_rerun()

    # Load selected history or upload new
    uploaded_file = st.file_uploader("📤 Upload CSV File", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        save_to_history(df)
        st.success("✅ File saved to history")
    elif selected_log:
        df = load_history_df(selected_log)
        st.info(f"📁 Loaded: {selected_log}")
    else:
        df = None

    if df is not None:
        st.subheader("📄 Uploaded Data")
        st.dataframe(df)

        # --- Anomaly Detection ---
        with st.spinner("Analyzing with AI..."):
            model = IsolationForest(contamination=0.2, random_state=42)
            model.fit(df.select_dtypes(include=np.number))
            df['anomaly'] = model.predict(df.select_dtypes(include=np.number))
            df['anomaly_label'] = df['anomaly'].map({1: "✅ Normal", -1: "⚠️ Suspicious"})

        st.subheader("📊 Detection Results")
        st.dataframe(df)

        st.subheader("⚠️ Suspicious Entries")
        st.dataframe(df[df['anomaly_label'] == "⚠️ Suspicious"])

        # --- Charts ---
        if st.checkbox("📈 Suspicion Score Over Time"):
            df['suspicion_score'] = df['bytes_sent'] + df['bytes_received']
            df['log_index'] = df.index
            fig1, ax1 = plt.subplots()
            ax1.plot(df['log_index'], df['suspicion_score'], color='orange')
            ax1.set_title("Suspicion Score Trend")
            st.pyplot(fig1)

        if st.checkbox("📊 Show Anomalies by User"):
            fig2, ax2 = plt.subplots(figsize=(12, 5))
            sns.countplot(data=df[df['anomaly_label'] == "⚠️ Suspicious"], x='username', ax=ax2)
            ax2.set_title("Suspicious Activity by User")
            plt.xticks(rotation=45)
            st.pyplot(fig2)

        if st.checkbox("🥧 Show Normal vs Suspicious Distribution"):
            fig3, ax3 = plt.subplots()
            labels = ['Normal', 'Suspicious']
            sizes = [
                len(df[df['anomaly_label'] == "✅ Normal"]),
                len(df[df['anomaly_label'] == "⚠️ Suspicious"])
            ]
            ax3.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['green', 'red'])
            st.pyplot(fig3)

        # --- Live Detection ---
        st.subheader("📡 Live Detection Simulation")
        for i in range(min(20, len(df))):
            log = df.iloc[i]
            st.write(f"👤 {log.get('username', 'Unknown')} | 🕒 {log['login_time']} | {log['anomaly_label']}")
            time.sleep(0.1)

        # --- Download Report ---
        st.subheader("📥 Download Anomaly Report")
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", csv, "anomaly_report.csv", "text/csv")

        # --- Stats ---
        st.subheader("📊 Stats Overview")
        st.metric("🔍 Total Records", len(df))
        st.metric("⚠️ Anomalies", len(df[df['anomaly_label'] == "⚠️ Suspicious"]))
        st.metric("✅ Normal", len(df[df['anomaly_label'] == "✅ Normal"]))

elif authentication_status is False:
    st.error("❌ Incorrect username or password")

elif authentication_status is None:
    st.warning("Please enter your credentials.")
