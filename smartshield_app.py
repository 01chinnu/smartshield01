# --- Updated SmartShield Intrusion Detection System ---
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
from cryptography.fernet import Fernet

st.set_page_config(page_title="SmartShield IDS", layout="wide")

# --- ENCRYPTION SETUP ---
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    key = f.read()
fernet = Fernet(key)

HISTORY_DIR = "history"
os.makedirs(HISTORY_DIR, exist_ok=True)

def save_to_history(df, original_filename):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_id = f"{original_filename}__{timestamp}"
    csv_path = os.path.join(HISTORY_DIR, f"{file_id}.csv")
    json_path = os.path.join(HISTORY_DIR, f"{file_id}.json")

    csv_data = df.to_csv(index=False).encode()
    with open(csv_path, "wb") as f:
        f.write(fernet.encrypt(csv_data))

    metadata = {
        "display_name": original_filename,
        "file_id": file_id,
        "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "record_count": len(df)
    }
    json_data = json.dumps(metadata, indent=2).encode()
    with open(json_path, "wb") as f:
        f.write(fernet.encrypt(json_data))

def list_saved_histories():
    items = []
    for file in os.listdir(HISTORY_DIR):
        if file.endswith(".json"):
            with open(os.path.join(HISTORY_DIR, file), "rb") as f:
                decrypted = fernet.decrypt(f.read()).decode()
                metadata = json.loads(decrypted)
                items.append((metadata["file_id"], metadata["display_name"], metadata))
    return sorted(items, key=lambda x: x[2]["uploaded_at"], reverse=True)

def load_history_df(file_id):
    with open(os.path.join(HISTORY_DIR, f"{file_id}.csv"), "rb") as f:
        decrypted = fernet.decrypt(f.read()).decode()
    from io import StringIO
    return pd.read_csv(StringIO(decrypted))

def delete_history_item(file_id):
    os.remove(os.path.join(HISTORY_DIR, f"{file_id}.csv"))
    os.remove(os.path.join(HISTORY_DIR, f"{file_id}.json"))

def clear_history():
    for file in os.listdir(HISTORY_DIR):
        os.remove(os.path.join(HISTORY_DIR, file))

# --- USER AUTHENTICATION ---
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
        elif not all([new_name, new_username, new_email, new_password]):
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

if "signup_mode" not in st.session_state:
    st.session_state.signup_mode = False
if st.sidebar.button("🔄 Toggle Sign Up / Login"):
    st.session_state.signup_mode = not st.session_state.signup_mode
if st.session_state.signup_mode:
    register_user()
    st.stop()

# --- LOGIN ---
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

name, authentication_status, username = authenticator.login("Login", "main")

# --- MAIN APP ---
if authentication_status:
    st.sidebar.markdown(f"👋 Welcome **{name}**")
    authenticator.logout("Logout", "sidebar")
    st.title("🔐 SmartShield – Intrusion Detection System")

    history = list_saved_histories()
    selected_log = None
    selected_logs = []

    st.sidebar.markdown("### 🕓 History (Select to Compare)")
    for file_id, display_name, meta in history:
        if st.sidebar.checkbox(display_name, key=f"check_{file_id}"):
            selected_logs.append(file_id)
        if st.sidebar.button(f"🗑️ Delete {display_name}", key=file_id + "_del"):
            delete_history_item(file_id)
            st.rerun()

    if history and st.sidebar.button("🧹 Clear All History"):
        clear_history()
        st.rerun()

    if selected_logs and st.sidebar.button("📊 Compare Selected Logs"):
        st.session_state["benchmark_mode"] = selected_logs

    if "benchmark_mode" in st.session_state:
        selected_ids = st.session_state["benchmark_mode"]
        st.subheader("📊 Benchmark Mode – Log Comparison")

        summary_rows = []
        for file_id in selected_ids:
            df_bench = load_history_df(file_id)
            df_num = df_bench.select_dtypes(include=np.number).dropna()
            model = IsolationForest(contamination='auto', random_state=42)
            model.fit(df_num)
            scores = model.decision_function(df_num)
            threshold = np.percentile(scores, 15)
            anomalies = (scores < threshold).sum()
            total = len(df_bench)
            top_users = df_bench.iloc[scores.argsort()[:anomalies]]["username"].value_counts().head(1)
            summary_rows.append({
                "File": file_id.split("__")[0],
                "Total Logs": total,
                "Anomalies": anomalies,
                "Top Suspicious User": top_users.index[0] if not top_users.empty else "N/A"
            })

        st.dataframe(pd.DataFrame(summary_rows))

        if st.button("🔁 Exit Benchmark Mode"):
            del st.session_state["benchmark_mode"]
            st.rerun()
        st.stop()

    uploaded_file = st.file_uploader("📤 Upload CSV File", type=["csv"])
    df = None
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        save_to_history(df, uploaded_file.name)
        st.success(f"✅ '{uploaded_file.name}' uploaded and saved.")
    elif not uploaded_file and history:
        selected_log = history[0][0]
        df = load_history_df(selected_log)
        st.info(f"📁 Loaded: {selected_log.split('__')[0]}")

    if df is not None:
        st.subheader("📄 Uploaded Data")
        st.dataframe(df)

        with st.spinner("Analyzing with adaptive ML model..."):
            df_num = df.select_dtypes(include=np.number).dropna()
            model = IsolationForest(contamination='auto', random_state=42)
            model.fit(df_num)
            scores = model.decision_function(df_num)
            threshold = np.percentile(scores, 15)
            df['anomaly_score'] = scores
            df['anomaly'] = (scores < threshold).astype(int)
            df['anomaly_label'] = df['anomaly'].map({0: "✅ Normal", 1: "⚠️ Suspicious"})

        st.subheader("📊 Detection Results")
        st.dataframe(df)

        st.subheader("⚠️ Suspicious Entries")
        st.dataframe(df[df['anomaly'] == 1])

        if st.checkbox("📈 Suspicion Score Over Time"):
            df['log_index'] = df.index
            fig1, ax1 = plt.subplots()
            ax1.plot(df['log_index'], df['anomaly_score'], color='orange')
            ax1.set_title("Suspicion Score Trend")
            st.pyplot(fig1)

        if st.checkbox("📊 Show Anomalies by User") and 'username' in df.columns:
            fig2, ax2 = plt.subplots(figsize=(12, 5))
            sns.countplot(data=df[df['anomaly'] == 1], x='username', ax=ax2)
            ax2.set_title("Suspicious Activity by User")
            plt.xticks(rotation=45)
            st.pyplot(fig2)

        if st.checkbox("🥧 Show Normal vs Suspicious Distribution"):
            fig3, ax3 = plt.subplots()
            sizes = df['anomaly'].value_counts(sort=False)
            ax3.pie(sizes, labels=['Normal', 'Suspicious'], autopct='%1.1f%%', colors=['green', 'red'])
            st.pyplot(fig3)

        st.subheader("📡 Live Detection Simulation")
        for i in range(min(20, len(df))):
            log = df.iloc[i]
            st.write(f"👤 {log.get('username', 'Unknown')} | 🕒 {log.get('login_time', '-') } | {log['anomaly_label']}")
            time.sleep(0.1)

        st.subheader("📥 Download Anomaly Report")
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", csv, "anomaly_report.csv", "text/csv")

        st.subheader("📊 Stats Overview")
        st.metric("🔍 Total Records", len(df))
        st.metric("⚠️ Anomalies", df['anomaly'].sum())
        st.metric("✅ Normal", len(df) - df['anomaly'].sum())

elif authentication_status is False:
    st.error("❌ Incorrect username or password")
elif authentication_status is None:
    st.warning("Please enter your credentials.")
