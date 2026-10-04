# 🛡️ SOC Log Analyzer

A cybersecurity project designed to practice **Security Operations Center (SOC) monitoring, authentication log analysis, and basic threat detection**.

The SOC Log Analyzer analyzes authentication events and identifies suspicious login behavior, including repeated failed login attempts, possible brute-force attacks, and successful logins following multiple failures.

The project includes both a **Python-based log analyzer** and an interactive **web-based SOC dashboard**.

---

## 📌 Project Overview

The analyzer processes authentication logs containing information such as:

- Timestamp
- Login event
- Username
- Source IP address

It analyzes these events to identify suspicious authentication patterns and assigns alerts based on the number and sequence of login attempts.

The project uses synthetic authentication logs for safe testing and learning purposes.

---

## 🚨 Detection Rules

The current detection engine uses four severity levels.

| Severity    | Detection                                      |
| ----------- | ---------------------------------------------- |
| 🟢 Low      | 1–4 failed login attempts from the same IP     |
| 🟡 Medium   | 5–9 failed login attempts from the same IP     |
| 🟠 High     | 10+ failed login attempts from the same IP     |
| 🔴 Critical | Successful login after 5+ consecutive failures |

### Low — Failed Login Activity

Records failed authentication activity from a source IP.

### Medium — Repeated Failed Login Attempts

Triggered when an IP address has **5 or more failed login attempts**.

### High — Possible Brute Force Attack

Triggered when an IP address has **10 or more failed login attempts**.

### Critical — Possible Account Compromise

Triggered when a successful login occurs after **5 or more consecutive failed attempts** from the same IP.

---

## 🖥️ SOC Dashboard

The web dashboard provides a SOC-style interface for monitoring authentication activity.

It displays:

- Total events
- Failed logins
- Security alerts
- Critical alerts
- Recent security events
- Source IP addresses
- Target accounts
- Alert severity
- Active detection rules

The dashboard automatically loads the sample log file, analyzes the events, and generates security alerts.

---

## 🔍 Example Detection

The sample logs contain repeated failed authentication attempts against the `admin` account from the same IP address.

Example:

```text
LOGIN_FAILED user=admin ip=192.168.1.25
LOGIN_FAILED user=admin ip=192.168.1.25
LOGIN_FAILED user=admin ip=192.168.1.25
...
LOGIN_SUCCESS user=admin ip=192.168.1.25
```

The analyzer can identify this activity as:

```text
[HIGH] Possible Brute Force Attack

Source IP: 192.168.1.25
Target Account: admin
Failed Attempts: 12
```

Because a successful login occurs after the repeated failures, the system can also identify a potential account compromise:

```text
[CRITICAL] Successful Login After Multiple Failures

Source IP: 192.168.1.25
Account: admin
Previous Failed Attempts: 12
```

The detection logic specifically tracks failed attempts by IP and records successful logins that occur after repeated failures.

---

## 🧰 Technologies Used

- **Python** — Log analysis and detection logic
- **HTML** — Dashboard structure
- **CSS** — Dashboard styling and responsive design
- **JavaScript** — Log processing and dynamic alerts
- **Visual Studio Code** — Development environment
- **Git** — Version control
- **GitHub** — Project repository

---

## 📁 Project Structure

```text
SOC-Log-Analyzer/
│
├── index.html
├── style.css
├── script.js
├── soc_analyzer.py
├── sample_logs.txt
└── README.md
```

### `soc_analyzer.py`

Python implementation of the SOC log analyzer.

It reads the authentication logs, counts successful and failed logins, tracks activity by IP address, and generates security alerts.

### `sample_logs.txt`

Synthetic authentication logs used to test the detection engine.

### `index.html`

Contains the structure of the SOC dashboard, including statistics, security alerts, log events, and detection rules.

### `style.css`

Provides the dark SOC-style interface, alert styling, event table, responsive layout, and dashboard components.

### `script.js`

Processes the sample logs in the browser, calculates security statistics, detects suspicious activity, and dynamically creates alert cards.

---

## ▶️ Running the Python Analyzer

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/SOC-Log-Analyzer.git
```

### 2. Navigate into the project

```bash
cd SOC-Log-Analyzer
```

### 3. Run the analyzer

```bash
python soc_analyzer.py
```

The program will load `sample_logs.txt`, analyze the authentication events, and display the results and security alerts in the terminal.

---

## 🌐 Running the SOC Dashboard

The dashboard loads `sample_logs.txt` using JavaScript, so it should be run through a local web server.

### Using VS Code Live Server

1. Open the project in Visual Studio Code.
2. Install the **Live Server** extension.
3. Open `index.html`.
4. Right-click the file.
5. Select **Open with Live Server**.

The dashboard will open in your browser and automatically analyze the sample logs.

---

## 📊 What I Learned

Through this project, I practiced:

- Security log analysis
- Authentication monitoring
- Brute-force detection
- IP-based event correlation
- Alert severity classification
- Python dictionaries and loops
- JavaScript data processing
- HTML/CSS dashboard development
- Git and GitHub version control
- Basic SOC detection concepts

One of the main concepts demonstrated by this project is that **individual security events may not appear suspicious by themselves, but analyzing multiple related events can reveal potentially malicious behavior.**

---

## ⚠️ Limitations

This is an **educational SOC monitoring project** and is not intended to replace a production SIEM or SOC platform.

Current limitations include:

- Simple threshold-based detection
- Synthetic authentication logs
- Limited log formats
- No real-time log ingestion
- No external threat intelligence
- No advanced correlation engine
- Potential false positives

A production SOC environment would require more advanced detection logic, additional log sources, time-based correlation, threat intelligence, and mechanisms for reducing false positives.

---

## 🚀 Future Improvements

Planned improvements could include:

- [ ] Log file upload
- [ ] Time-based brute-force detection
- [ ] Alert filtering
- [ ] Search functionality
- [ ] Additional attack detection rules
- [ ] Security event charts
- [ ] Incident report generation
- [ ] Support for additional log formats
- [ ] Real-time log monitoring
- [ ] Threat intelligence integration
- [ ] More advanced event correlation

---

## 🔐 Security & Privacy

All log data included in this project is **synthetic** and is used only for educational and testing purposes.

No real passwords, credentials, or private authentication data are required to run the project.

---

## 👩‍💻 Author

mohamed elmutasim magzoub&#x20;

IT student&#x20;

This project was created as part of my cybersecurity and technical portfolio to demonstrate practical experience with **log analysis, security monitoring, threat detection, Python, and web development**.
