# 🛡️ CyberShield — Security Activity Dashboard

A lightweight, web-based cybersecurity monitoring dashboard built with **Python** and **Streamlit**. CyberShield gives security analysts a centralised, real-time view of user login activity and automatically flags suspicious IP addresses using a rule-based detection engine.

---

## 📸 Overview

CyberShield displays four KPI metric cards, a filterable login records table, two analytical bar charts, and a colour-coded security alerts panel — all styled with a GitHub-inspired dark theme.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📊 **KPI Metric Cards** | Total Logins, Successful Logins, Failed Logins, and live Suspicious Activities count |
| 📋 **Login Records Table** | Colour-coded table (green = Success, red = Failed) with a dropdown filter (All / Success / Failed) |
| 📈 **Login Result Breakdown Chart** | Bar chart comparing successful vs. failed login totals |
| 🗺️ **Failed Logins by IP Chart** | Ranked bar chart showing which IPs generated the most failures |
| 🚨 **Rule-Based Security Alerts** | Automatically flags IPs with 3+ failed logins, sorted by risk level |
| 🔴🟡🟢 **Three-Tier Risk Scoring** | High (≥ 10 failures) · Medium (5–9) · Low (3–4), each with colour, icon, and plain-English reason |
| 🎨 **Dark Theme UI** | Custom CSS injected via Streamlit for a GitHub-style dark colour scheme |
| 💾 **Session-State Persistence** | Loaded data persists across interactions without page reloads |

---

## 🛠️ Tech Stack

- **Python 3** — core language and detection logic
- **Streamlit** — web framework, UI widgets, layout, and session state
- **pandas** — DataFrame operations, filtering, value counts, and cell styling
- **HTML / CSS** — custom dark theme and alert cards via `st.markdown(unsafe_allow_html=True)`

---

## 📁 Project Structure

```
.
├── app.py        # Main application — all UI, data, and detection logic
└── README.md     # This file
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip

### Installation

```bash
# 1. Clone or download this repository
git clone <your-repo-url>
cd <repo-folder>

# 2. Install dependencies
pip install streamlit pandas

# 3. Run the dashboard
streamlit run app.py
```

The app will open automatically in your browser at `http://localhost:8501`.

---

## ⚙️ How It Works

1. **Load Data** — Click **🔄 Generate Sample Data** to populate 20 sample login records into session state.
2. **Failure Counting** — A Python loop counts failed login attempts per IP address into a dictionary.
3. **Risk Classification** — Each IP with ≥ 3 failures is assigned a risk level via `get_risk_level()`.
4. **KPI Cards** — Four metric cards update, including the live Suspicious Activities counter.
5. **Table & Filter** — Records are rendered as a styled DataFrame; a dropdown filters by result type.
6. **Charts** — Two side-by-side bar charts visualise result breakdown and per-IP failure counts.
7. **Alert Cards** — Each flagged IP renders a colour-bordered card with IP, usernames tried, failure count, risk level, and reason text.

### Detection Thresholds

| Failures from one IP | Risk Level | Meaning |
|---|---|---|
| ≥ 10 | 🔴 High | Likely automated brute-force attack |
| 5 – 9 | 🟡 Medium | Suspicious — warrants investigation |
| 3 – 4 | 🟢 Low | Unusual — monitor, do not block immediately |

> **Note:** Multiple failed logins can also result from forgotten passwords or misconfigured applications. Alerts are a starting point for investigation — not a final verdict.

---

## 🔮 Future Scope

- **Live log ingestion** — connect to `auth.log`, Windows Event Log, or a syslog server
- **ML anomaly detection** — Isolation Forest or time-series clustering for behavioural anomalies
- **IP geolocation & threat intel** — enrich alerts with country, ISP, and AbuseIPDB scores
- **Automated response** — one-click firewall block or webhook to Jira / PagerDuty
- **User behaviour analytics (UBA)** — baseline per-user patterns and alert on deviations
- **Historical trend charts** — time-series views of login volumes and failure rates
- **Authentication & RBAC** — protect the dashboard and restrict response actions
- **Export / reporting** — CSV / PDF download of filtered records and alerts

---

## 📄 License

This project was created as part of the **IBM Cybersecurity Bootcamp**.
