import streamlit as st
import pandas as pd

# --- Page Configuration ---
st.set_page_config(
    page_title="CyberShield",
    page_icon="🛡️",
    layout="wide"
)

# --- Dark Theme Custom CSS ---
st.markdown("""
    <style>
        /* Main background */
        .stApp {
            background-color: #0d1117;
            color: #c9d1d9;
        }

        /* Title styling */
        .dashboard-title {
            font-size: 2.4rem;
            font-weight: 700;
            color: #58a6ff;
            margin-bottom: 0;
        }

        .dashboard-subtitle {
            font-size: 1rem;
            color: #8b949e;
            margin-top: 0.2rem;
            margin-bottom: 2rem;
        }

        /* Metric card styling */
        div[data-testid="metric-container"] {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px 24px;
        }

        /* Metric label */
        div[data-testid="metric-container"] label {
            color: #8b949e !important;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Metric value */
        div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
            color: #c9d1d9 !important;
            font-size: 2rem;
            font-weight: 700;
        }

        /* Divider */
        hr {
            border-color: #30363d;
        }

        /* Table header */
        thead tr th {
            background-color: #161b22 !important;
            color: #58a6ff !important;
        }

        /* Table rows */
        tbody tr {
            background-color: #0d1117 !important;
            color: #c9d1d9 !important;
        }
    </style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# 20 fake login records — defined first so the detection rule can use them.
# IP 203.0.113.99 has 5 failed attempts and will be flagged as suspicious.
# ---------------------------------------------------------------------------
SAMPLE_RECORDS = [
    {"Time": "2026-10-30 08:01:12", "Username": "alice",    "IP Address": "192.168.1.10",  "Result": "Success"},
    {"Time": "2026-10-30 08:03:45", "Username": "bob",      "IP Address": "192.168.1.22",  "Result": "Success"},
    {"Time": "2026-10-30 08:07:30", "Username": "carol",    "IP Address": "10.0.0.5",      "Result": "Success"},
    {"Time": "2026-10-30 08:12:00", "Username": "dave",     "IP Address": "192.168.1.33",  "Result": "Failed"},
    {"Time": "2026-10-30 08:14:15", "Username": "admin",    "IP Address": "203.0.113.99",  "Result": "Failed"},  # suspicious IP
    {"Time": "2026-10-30 08:14:52", "Username": "admin",    "IP Address": "203.0.113.99",  "Result": "Failed"},  # suspicious IP
    {"Time": "2026-10-30 08:15:10", "Username": "root",     "IP Address": "203.0.113.99",  "Result": "Failed"},  # suspicious IP
    {"Time": "2026-10-30 08:15:33", "Username": "root",     "IP Address": "203.0.113.99",  "Result": "Failed"},  # suspicious IP
    {"Time": "2026-10-30 08:15:58", "Username": "sysadmin", "IP Address": "203.0.113.99",  "Result": "Failed"},  # suspicious IP
    {"Time": "2026-10-30 08:20:05", "Username": "eve",      "IP Address": "10.0.0.8",      "Result": "Success"},
    {"Time": "2026-10-30 08:25:44", "Username": "frank",    "IP Address": "192.168.1.50",  "Result": "Success"},
    {"Time": "2026-10-30 08:31:00", "Username": "grace",    "IP Address": "172.16.0.3",    "Result": "Success"},
    {"Time": "2026-10-30 08:35:17", "Username": "henry",    "IP Address": "192.168.1.77",  "Result": "Failed"},
    {"Time": "2026-10-30 08:40:22", "Username": "iris",     "IP Address": "10.0.0.12",     "Result": "Success"},
    {"Time": "2026-10-30 08:44:09", "Username": "jack",     "IP Address": "192.168.1.88",  "Result": "Success"},
    {"Time": "2026-10-30 08:50:31", "Username": "karen",    "IP Address": "172.16.0.7",    "Result": "Success"},
    {"Time": "2026-10-30 08:55:03", "Username": "leo",      "IP Address": "192.168.1.91",  "Result": "Success"},
    {"Time": "2026-10-30 09:01:47", "Username": "mia",      "IP Address": "10.0.0.20",     "Result": "Success"},
    {"Time": "2026-10-30 09:05:55", "Username": "nick",     "IP Address": "192.168.1.100", "Result": "Failed"},
    {"Time": "2026-10-30 09:10:12", "Username": "olivia",   "IP Address": "172.16.0.15",   "Result": "Success"},
]

# ---------------------------------------------------------------------------
# SUSPICIOUS ACTIVITY DETECTION RULE
# ---------------------------------------------------------------------------
# Rule: if the same IP address has 5 or more failed login attempts,
#       it is considered suspicious (possible brute-force attack).
# This uses only plain Python — no machine learning, no external systems.
# ---------------------------------------------------------------------------

# The threshold: how many failed attempts from one IP counts as suspicious
SUSPICIOUS_THRESHOLD = 5

# Step 1 — count failed logins per IP address using a plain dictionary.
# We only run the rule if the user has loaded data (records are in session_state).
failed_per_ip = {}   # key = IP address, value = number of failed attempts

# Use the records stored in session_state if available, otherwise an empty list
records_to_check = st.session_state.get("records", [])

for record in records_to_check:
    if record["Result"] == "Failed":
        ip = record["IP Address"]
        # If we've seen this IP before, add 1; otherwise start counting at 1
        if ip in failed_per_ip:
            failed_per_ip[ip] = failed_per_ip[ip] + 1
        else:
            failed_per_ip[ip] = 1

# Step 2 — assign a risk level based on how many failures came from one IP.
# These thresholds are simple rules — not machine learning.
#   10 or more failures → HIGH risk   (very aggressive, likely automated)
#   5 to 9 failures     → MEDIUM risk (suspicious, worth investigating)
#   3 to 4 failures     → LOW risk    (unusual but could be a forgotten password)
def get_risk_level(count):
    if count >= 10:
        return "High"
    elif count >= 5:
        return "Medium"
    else:
        return "Low"

# Step 3 — collect every IP with 3 or more failures into an alert list.
# Each alert is a dictionary with all the details we want to display.
ALERT_THRESHOLD = 3   # minimum failures to generate any alert

alerts = []   # list of alert dictionaries

for ip, count in failed_per_ip.items():
    if count >= ALERT_THRESHOLD:
        # Find the usernames that failed from this IP (there may be more than one)
        usernames_tried = []
        for record in records_to_check:
            if record["IP Address"] == ip and record["Result"] == "Failed":
                if record["Username"] not in usernames_tried:
                    usernames_tried.append(record["Username"])

        # Build the alert dictionary
        alert = {
            "ip":        ip,
            "usernames": usernames_tried,
            "count":     count,
            "risk":      get_risk_level(count),
        }
        alerts.append(alert)

# Step 4 — sort alerts so the highest risk appears first
# High → Medium → Low using a fixed order dictionary
RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2}
alerts.sort(key=lambda a: RISK_ORDER[a["risk"]])

# Step 5 — the dashboard card counts only IPs that meet the original suspicious threshold
suspicious_ips        = [a["ip"] for a in alerts if a["count"] >= SUSPICIOUS_THRESHOLD]
suspicious_activities = len(suspicious_ips)

# ---------------------------------------------------------------------------
# DASHBOARD UI
# ---------------------------------------------------------------------------

# --- Header ---
st.markdown('<p class="dashboard-title">🛡️ CyberShield</p>', unsafe_allow_html=True)
st.markdown('<p class="dashboard-subtitle">Security Activity Dashboard — Real-time login & threat monitoring</p>', unsafe_allow_html=True)
st.markdown("---")

# --- Static counters (from a real system these would come from a database) ---
total_logins      = 1_482
successful_logins = 1_390
failed_logins     = 72
# suspicious_activities is calculated live by the detection rule above

# --- Four Metric Cards ---
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(label="🔑 Total Logins", value=f"{total_logins:,}")

with col2:
    st.metric(label="✅ Successful Logins", value=f"{successful_logins:,}")

with col3:
    st.metric(label="❌ Failed Logins", value=f"{failed_logins:,}")

with col4:
    # This number updates automatically when data is loaded
    st.metric(label="⚠️ Suspicious Activities", value=f"{suspicious_activities:,}")

st.markdown("---")

# --- Login Records Section ---
st.subheader("📋 Login Records")
st.caption("Click the button below to load the sample login data.")

# Button to load / refresh the table
if st.button("🔄 Generate Sample Data"):
    # Store the records in session_state so they persist after the button click
    st.session_state["records"] = SAMPLE_RECORDS

# Show the table if records are available in session_state
if "records" in st.session_state:
    df = pd.DataFrame(st.session_state["records"])

    # --- Filter: login result (Success / Failed / All) ---
    # st.selectbox renders a dropdown — the user picks one option
    result_filter = st.selectbox(
        "Filter by login result:",
        options=["All", "Success", "Failed"],   # choices shown in the dropdown
        key="result_filter"                      # unique key so Streamlit tracks it
    )

    # Apply the filter — if "All" is selected we keep every row unchanged
    if result_filter == "All":
        filtered_df = df
    else:
        # Keep only rows where the Result column matches what the user chose
        filtered_df = df[df["Result"] == result_filter]

    # Colour the Result column: green for Success, red for Failed
    def colour_result(val):
        colour = "#3fb950" if val == "Success" else "#f85149"
        return f"color: {colour}; font-weight: bold"

    styled_df = filtered_df.style.map(colour_result, subset=["Result"])
    st.dataframe(styled_df, use_container_width=True, hide_index=True)

    # Quick summary below the table (reflects the active filter)
    total   = len(filtered_df)
    success = (filtered_df["Result"] == "Success").sum()
    failed  = (filtered_df["Result"] == "Failed").sum()
    st.caption(f"Showing {total} records — ✅ {success} successful · ❌ {failed} failed")

st.markdown("---")

# ---------------------------------------------------------------------------
# CHARTS SECTION
# ---------------------------------------------------------------------------
st.subheader("📊 Login Activity Charts")

if "records" not in st.session_state:
    st.info("ℹ️ Load the sample data first by clicking **🔄 Generate Sample Data** above.")
else:
    # Build a fresh DataFrame from the stored records (unfiltered — charts show all data)
    chart_df = pd.DataFrame(st.session_state["records"])

    chart_col1, chart_col2 = st.columns(2)

    # ------------------------------------------------------------------
    # CHART 1 — Login Result Breakdown (bar chart)
    # ------------------------------------------------------------------
    # What it shows: how many logins were successful vs failed overall.
    # Why it helps: gives an instant sense of the success/failure ratio.
    #               A sudden spike in failures can indicate an attack.
    # ------------------------------------------------------------------
    with chart_col1:
        st.markdown("**Login Result Breakdown**")
        st.caption(
            "Compares the number of successful logins to failed ones. "
            "A high failure count relative to successes may indicate unusual activity."
        )

        # Count occurrences of each result value using pandas value_counts()
        result_counts = chart_df["Result"].value_counts()

        # Build a small DataFrame with two columns: Result and Count
        # reset_index() turns the Series index into a regular column
        result_chart_df = result_counts.reset_index()
        result_chart_df.columns = ["Result", "Count"]

        # st.bar_chart uses the index as the x-axis, so set Result as the index
        result_chart_df = result_chart_df.set_index("Result")

        st.bar_chart(result_chart_df, color=["#58a6ff"])

    # ------------------------------------------------------------------
    # CHART 2 — Failed Login Attempts by IP Address (bar chart)
    # ------------------------------------------------------------------
    # What it shows: which IP addresses had the most failed login attempts.
    # Why it helps: an IP with many failures stands out immediately —
    #               it is much easier to spot than scanning a raw table.
    # ------------------------------------------------------------------
    with chart_col2:
        st.markdown("**Failed Logins by IP Address**")
        st.caption(
            "Shows how many failed attempts came from each IP address. "
            "An IP with a very tall bar is worth investigating as a potential threat source."
        )

        # Keep only failed login rows
        failed_df = chart_df[chart_df["Result"] == "Failed"]

        # Count how many failures per IP, then sort highest first
        ip_counts = failed_df["IP Address"].value_counts().sort_values(ascending=False)

        # Convert to a DataFrame for st.bar_chart
        ip_chart_df = ip_counts.reset_index()
        ip_chart_df.columns = ["IP Address", "Failed Attempts"]
        ip_chart_df = ip_chart_df.set_index("IP Address")

        st.bar_chart(ip_chart_df, color=["#f85149"])

st.markdown("---")

# ---------------------------------------------------------------------------
# SECURITY ALERTS SECTION
# ---------------------------------------------------------------------------
st.subheader("🚨 Security Alerts")

# Important disclaimer shown at the top of this section
st.markdown("""
> **⚠️ Important note:** A suspicious login pattern does **not** automatically
> prove a cyberattack. Multiple failed logins can also happen because someone
> forgot their password, or a device is retrying with old credentials.
> These alerts are a starting point for investigation — not a final verdict.
""")

if "records" not in st.session_state:
    # No data loaded yet — prompt the user
    st.info("ℹ️ Load the sample data first by clicking **🔄 Generate Sample Data** above.")

elif len(alerts) == 0:
    # Data is loaded but nothing reached even the low-alert threshold
    st.success("✅ No suspicious activity detected in the current records.")

else:
    # --- Risk level filter dropdown ---
    # The user can choose to see all alerts or only one risk level
    all_risk_levels = ["All"] + sorted(set(a["risk"] for a in alerts), key=lambda r: RISK_ORDER[r])
    risk_filter = st.selectbox(
        "Filter alerts by risk level:",
        options=all_risk_levels,
        key="risk_filter"
    )

    # Apply the filter — show all alerts or only the selected risk level
    if risk_filter == "All":
        filtered_alerts = alerts
    else:
        filtered_alerts = [a for a in alerts if a["risk"] == risk_filter]

    if len(filtered_alerts) == 0:
        st.info(f"No {risk_filter} risk alerts in the current records.")

    # --- Risk level colour and icon reference (plain dictionaries) ---
    RISK_COLOUR = {
        "High":   "#f85149",   # red
        "Medium": "#d29922",   # amber/yellow
        "Low":    "#3fb950",   # green
    }
    RISK_ICON = {
        "High":   "🔴",
        "Medium": "🟡",
        "Low":    "🟢",
    }
    RISK_REASON = {
        "High":   (
            "10 or more failed attempts from a single IP in a short window. "
            "This strongly suggests an automated brute-force tool cycling "
            "through a password list."
        ),
        "Medium": (
            f"5–9 failed attempts from a single IP, targeting multiple usernames "
            f"(e.g. 'admin', 'root'). This is above the normal threshold of "
            f"{SUSPICIOUS_THRESHOLD} and warrants investigation."
        ),
        "Low": (
            "3–4 failed attempts from a single IP. Could be a forgotten password "
            "or a misconfigured application. Monitor but do not block immediately."
        ),
    }

    # Display one alert card per flagged IP (using the filtered list)
    for alert in filtered_alerts:
        ip        = alert["ip"]
        count     = alert["count"]
        risk      = alert["risk"]
        usernames = ", ".join(alert["usernames"])   # join list into one string
        colour    = RISK_COLOUR[risk]
        icon      = RISK_ICON[risk]
        reason    = RISK_REASON[risk]

        # Draw a coloured left-border card using HTML
        # (plain st.warning only supports one colour — this gives us three)
        st.markdown(f"""
            <div style="
                border-left: 4px solid {colour};
                background-color: #161b22;
                border-radius: 6px;
                padding: 16px 20px;
                margin-bottom: 14px;
            ">
                <div style="font-size:1.05rem; font-weight:700; color:{colour};">
                    {icon} {risk} Risk — IP Address: <code>{ip}</code>
                </div>
                <table style="margin-top:10px; border-collapse:collapse; width:100%;">
                    <tr>
                        <td style="color:#8b949e; width:200px; padding:4px 0;">IP Address</td>
                        <td style="color:#c9d1d9;"><code>{ip}</code></td>
                    </tr>
                    <tr>
                        <td style="color:#8b949e; padding:4px 0;">Usernames tried</td>
                        <td style="color:#c9d1d9;">{usernames}</td>
                    </tr>
                    <tr>
                        <td style="color:#8b949e; padding:4px 0;">Failed attempts</td>
                        <td style="color:{colour}; font-weight:bold;">{count}</td>
                    </tr>
                    <tr>
                        <td style="color:#8b949e; padding:4px 0;">Risk level</td>
                        <td style="color:{colour}; font-weight:bold;">{icon} {risk}</td>
                    </tr>
                    <tr>
                        <td style="color:#8b949e; padding:4px 0; vertical-align:top;">Reason</td>
                        <td style="color:#c9d1d9;">{reason}</td>
                    </tr>
                </table>
            </div>
        """, unsafe_allow_html=True)
