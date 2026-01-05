# 🔐 Adaptive Authentication & Threat Monitoring System

A **SOC-style, Zero-Trust authentication system** that goes beyond basic login functionality by continuously monitoring **user behavior**, tracking **unregistered / malicious actors**, enforcing **admin-controlled blocking**, and supporting **audit log export for compliance and security operations**.

This project demonstrates **real-world cybersecurity thinking** used in Security Operations Centers (SOC), not just a simple authentication flow.

---

## 🚀 Key Features

### 👤 Secure User Authentication
- Email-only user registration and login
- Secure password hashing using **bcrypt**
- Session-based authentication
- Continuous monitoring after successful login

### 🧠 Behavioral Security & Threat Detection
- Tracks:
  - IP address
  - Device / User-Agent
  - Login time
  - User behavior
- Detects suspicious patterns such as:
  - Off-hours access
  - Automated tools (curl, bots)
  - New or unknown devices

### 🚨 Unregistered / Attacker Monitoring
- Logs all login attempts from **unknown users**
- Assigns **threat scores** to unregistered actors
- Displays attacker telemetry **only to the admin**
- Helps identify reconnaissance and brute-force attempts

### 🛡️ Admin-Only Security Dashboard
- Separate admin authentication
- View registered users with trust levels
- Monitor suspicious and unregistered activity
- Manually block **email addresses or IPs**
- Blocking is **strictly enforced** (blocked entities cannot access the system)

### 📤 Audit Log Export (Compliance Feature)
- Export registered user logs as **CSV**
- Export threat activity logs as **CSV**
- Designed for:
  - SOC investigations
  - Incident response
  - Compliance reviews

---

## 🧩 Technology Stack

- **Backend:** Python, Flask  
- **Database:** SQLite  
- **Security:** bcrypt (password hashing)  
- **Frontend:** HTML, CSS (custom SOC-style UI)  

---

## 📁 Project Structure

adaptive_auth_threat_monitor/
│
├── app.py
├── requirements.txt
├── database.db (auto-created)
│
├── templates/
│ ├── login.html
│ ├── register.html
│ ├── success.html
│ ├── admin_login.html
│ └── admin_dashboard.html
│
└── static/
└── style.css

yaml
Copy code

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/adaptive-auth-threat-monitor.git
cd adaptive-auth-threat-monitor
2️⃣ Install Dependencies
bash
Copy code
python3 -m pip install -r requirements.txt
3️⃣ (Recommended) Reset Database
bash
Copy code
rm database.db
This ensures the database schema matches the latest version of the project.

4️⃣ Run the Application
bash
Copy code
python3 app.py
🌐 Application Access
User Login:
http://127.0.0.1:5000

Admin Login:
http://127.0.0.1:5000/admin

Admin Password

css
Copy code
Admin@123
