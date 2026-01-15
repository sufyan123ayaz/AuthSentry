🔐 Brute Force Login Defense Simulator (Level-2)

A cybersecurity simulation project that demonstrates how brute force login attacks occur and how modern security mechanisms can detect and prevent them using rate limiting, account lockout, OTP-based 2FA, and real-time monitoring.

📌 Problem Statement

Many real-world applications are vulnerable to brute force attacks due to:
Weak authentication handling
No rate limiting on login attempts
No account lockout mechanism
Lack of monitoring and alerting systems

Attackers can repeatedly try username–password combinations until they gain unauthorized access, leading to:

Account compromise
Data breaches

Privacy violations

❗ Core Problem

How can we simulate brute force attacks and also demonstrate effective defensive controls used in real-world systems?

🎯 Project Objective

This project is designed to:

Simulate brute force login behavior

Detect repeated failed login attempts
Apply account and IP-based lockout
Enforce OTP-based second-factor authentication
Log all authentication events
Provide real-time SOC-style monitoring dashboard

🧠 Why This Project Was Built (Problem → Solution Mapping)
Problem	Solution Implemented
No password protection	Passwords hashed using bcrypt
Unlimited login attempts	Rate limiting implemented
Repeated user attacks	Account lockout system
Same IP attacking multiple users	IP-based blocking
Stolen password risk	OTP-based 2FA
No monitoring	Streamlit SOC dashboard
No admin control	Admin unblock panel
🛠️ Technologies Used
🔧 Backend

Python

Flask – Web application framework

SQLite – Lightweight database

bcrypt – Secure password hashing

🔐 Security Layer

User-based rate limiting

IP-based rate limiting

Temporary account lockout

OTP generation & verification

Forensic event logging

📊 Monitoring

Streamlit – SOC-style dashboard

📁 Project Structure
bruteforce_simulator/
│
├── app.py            # Flask login system + OTP + admin panel
├── security.py       # All security logic (rate limiting, OTP, logs)
├── dashboard.py      # Streamlit SOC dashboard
├── create_user.py    # One-time user creation
├── database.db       # SQLite database
├── requirements.txt
└── README.md

⚙️ How the System Works (Step-by-Step Flow)
✅ Step 1: User Creation (Admin)

Admin creates users using:

python create_user.py

Passwords are:

Never stored in plain text
Hashed using bcrypt before saving

✅ Step 2: Login Attempt (Flask)

User enters:

Username
Password

System checks:

Is IP blocked?
Is user account locked?
Is password valid?

❌ Step 3: Failed Login Handling

On wrong password:
User attempt counter increases
IP attempt counter increases
Events are logged

If limit exceeded:

User or IP gets temporarily blocked

🔐 Step 4: OTP-Based Two-Factor Authentication

On correct password:
System generates 6-digit OTP
OTP is temporarily stored
User must verify OTP to complete login
This simulates real-world 2FA systems.

✅ Step 5: Successful Login

After OTP verification:
User session created
Attempts reset
Admin users can access admin panel

🧰 Step 6: Admin Panel

Admin can:
View blocked users
View blocked IPs
Manually unblock them

📊 Step 7: SOC Dashboard (Streamlit)

Run using:

streamlit run dashboard.py

Dashboard shows:

Failed attempts per user
Blocked users
Blocked IPs
Forensic authentication logs

This simulates Security Operations Center (SOC) monitoring.

🔒 Security Concepts Demonstrated

✔ Password Hashing
✔ Rate Limiting
✔ Account Lockout
✔ IP Reputation Blocking
✔ Two-Factor Authentication
✔ Event Logging
✔ SOC Monitoring

🎓 Academic Relevance

This project is suitable for:
Cybersecurity labs
Secure coding assignments
Penetration testing demonstrations
Authentication system studies
It aligns with topics such as:
Authentication mechanisms
Intrusion detection
Access control
Security monitoring

🚀 Possible Future Enhancements

CAPTCHA after repeated failures
Email/SMS OTP delivery
Machine learning based anomaly detection
Geo-location based IP blocking
SIEM integration (Splunk/ELK format logs)
JWT-based session handling
Password strength enforcement

⚠️ Ethical Use Disclaimer

This project is created for educational and defensive purposes only.
It must NOT be used for:
Unauthorized access
Hacking real systems
Credential stuffing
Always perform testing only in controlled lab environments.

🏁 Conclusion

This Brute Force Login Defense Simulator demonstrates how simple authentication systems can be hardened using layered security controls. It provides practical exposure to:
How brute force attacks occur
How they are detected
How systems respond in real time

It bridges the gap between theoretical cybersecurity concepts and real-world defensive implementation.

👨‍💻 Author ( Muhammad Sufyan Ayaz )

Developed as a cybersecurity learning project for practical understanding of:
Secure authentication
Intrusion prevention
SOC-style monitoring
