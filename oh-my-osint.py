# oh_my_osint_llm_api.py
import streamlit as st
import subprocess
import os
import json
import shutil
import requests
import re
from dotenv import load_dotenv
import google.generativeai as genai

# --- Load environment variables from .env ---
load_dotenv()
genai_api_key = os.getenv("GOOGLE_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# --- Configure Gemini ---
genai.configure(api_key=genai_api_key)
model = genai.GenerativeModel("gemini-2.5-flash-preview-04-17")

# --- CLI Tool Capabilities Map ---
TOOL_CAPABILITIES = {
    "sherlock": {
        "base": "sherlock {target}",
        "flags": ["--verbose", "--print-found"]
    },
    "holehe": {
        "base": "holehe {target}",
        "flags": ["--json", "--only-used"]
    },
    "socialscan": {
        "base": "socialscan {target}",
        "flags": ["--platforms all"]
    },
    "pwned": {
        "base": "pwned {target}",
        "flags": ["--no-colors"]
    },
    "theHarvester": {
        "base": "theHarvester -d {target}",
        "flags": ["-b all", "-l 100", "-v"]
    },
    "amass": {
        "base": "amass enum -d {target}",
        "flags": ["-ip", "-brute", "-o amass_output.txt"]
    },
    "sublist3r": {
        "base": "sublist3r -d {target}",
        "flags": ["-v", "-o subdomains.txt"]
    },
    "dnsrecon": {
        "base": "dnsrecon -d {target}",
        "flags": ["-t std", "-a", "-D /usr/share/wordlists/dnsmap.txt"]
    },
    "waybackurls": {
        "base": "echo {target} | waybackurls",
        "flags": []
    }
}

# --- Tool Installation Function ---
def install_tools():
    tool_commands = {
        "sherlock": "pipx install sherlock",
        "holehe": "pipx install holehe",
        "socialscan": "pipx install socialscan",
        "pwned": "pipx install pwned-cli",
        "theHarvester": "apt install -y theharvester",
        "amass": "apt install -y amass",
        "sublist3r": "apt install -y sublist3r",
        "dnsrecon": "apt install -y dnsrecon",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest"
    }
    for tool, command in tool_commands.items():
        if shutil.which(tool) is None:
            try:
                st.write(f"🔧 Installing {tool}...")
                subprocess.run(command, shell=True, check=True)
                st.success(f"✅ {tool} installed successfully.")
            except Exception as e:
                st.error(f"❌ Failed to install {tool}: {e}")

# --- Ask Gemini for Tools and Flags ---
def ask_gemini_for_tools(target_type, target_value, available_tools):
    cli_tool_instructions = []
    for tool in available_tools:
        if tool in TOOL_CAPABILITIES:
            base = TOOL_CAPABILITIES[tool]['base']
            flags = TOOL_CAPABILITIES[tool]['flags']
            cli_tool_instructions.append(f"- {tool}: base command = '{base}', available flags = {flags}")

    prompt = f"""
You are an OSINT analyst assistant.
The user is investigating:
Target type: {target_type}
Target value: {target_value}

Select CLI tools and free APIs to run.
Return a JSON array with:
- name: the tool name
- type: 'cli' or 'api'
- flags: list of selected flags (for CLI)
- url: full URL if type is 'api'

CLI tools and their capabilities:
{chr(10).join(cli_tool_instructions)}

APIs available:
- crt.sh: https://crt.sh/?q={target_value}&output=json
- ipinfo.io: https://ipinfo.io/{target_value}/json
- AbuseIPDB: https://api.abuseipdb.com/api/v2/check?ipAddress={target_value}
- viewdns.info: https://viewdns.info/reverseip/?host={target_value}&t=1
- shodan.io: https://api.shodan.io/shodan/host/{target_value}?key=SHODAN_API_KEY

Only include valid tools for the target type. Output a JSON array using double quotes for all keys and string values.
"""
    response = model.generate_content(prompt)
    try:
        text = response.text.strip()
        json_text = text[text.find("["):text.rfind("]") + 1]
        return json.loads(json_text)
    except Exception as e:
        st.error(f"Gemini JSON parse error: {e}")
        return []

# --- IP Extractor ---
def extract_ips(output):
    return list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output)))

# --- User Interface ---
st.title("🔍 Gemini-Powered OSINT Toolchain")

if st.sidebar.button("🛠️ Install Tools"):
    install_tools()

target_type = st.selectbox("Select Target Type", ["username", "email", "domain", "IP address", "phone number"])
target_value = st.text_input("Enter Target Value")

if target_value:
    with st.spinner("🧠 Asking Gemini to decide on tools and flags..."):
        available_tools = list(TOOL_CAPABILITIES.keys())
        recommendations = ask_gemini_for_tools(target_type, target_value, available_tools)

    st.subheader("🤖 Gemini's Suggested Tools & Flags")
    selected_items = []
    for idx, item in enumerate(recommendations):
        if st.checkbox(f"{item['name']} ({item['type']})", key=f"tool_{idx}", value=True):
            selected_items.append(item)

    tool_outputs = []
    all_ips = set()

    if selected_items:
        st.subheader("🚀 Execution Results")
        for item in selected_items:
            try:
                if item['type'] == 'cli':
                    tool = item['name']
                    base_cmd = TOOL_CAPABILITIES[tool]['base'].replace("{target}", target_value)
                    flags = ' '.join(item.get('flags', []))
                    command = f"{base_cmd} {flags}".strip()
                    st.code(f"$ {command}", language="bash")
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=90)
                    output = result.stdout or result.stderr or "No output"
                    st.code(output)
                    tool_outputs.append({"tool": tool, "type": "cli", "command": command, "output": output})
                    if target_type == "domain":
                        all_ips.update(extract_ips(output))
                elif item['type'] == 'api':
                    url = item.get('url', '').replace("{target}", target_value)
                    st.code(f"GET {url}", language="bash")
                    r = requests.get(url, timeout=15)
                    if r.ok:
                        st.code(r.text, language="json")
                        tool_outputs.append({"tool": item['name'], "type": "api", "command": url, "output": r.text})
                    else:
                        st.error(f"API error {r.status_code}: {r.text}")
            except Exception as e:
                st.error(f"❌ Skipping {item['name']} due to error: {e}")

    # --- Run IP-based APIs if IPs were found ---
    if all_ips:
        for ip in all_ips:
            try:
                url = f"https://ipinfo.io/{ip}/json"
                st.code(f"GET {url}", language="bash")
                r = requests.get(url, timeout=10)
                if r.ok:
                    st.code(r.text, language="json")
                    tool_outputs.append({"tool": "ipinfo.io", "type": "api", "command": url, "output": r.text})
            except Exception as e:
                st.error(f"ipinfo error: {e}")
            try:
                abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
                headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                st.code(f"GET {abuse_url}", language="bash")
                r = requests.get(abuse_url, headers=headers, timeout=10)
                if r.ok:
                    st.code(r.text, language="json")
                    tool_outputs.append({"tool": "AbuseIPDB", "type": "api", "command": abuse_url, "output": r.text})
            except Exception as e:
                st.error(f"AbuseIPDB error: {e}")
            try:
                shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
                st.code(f"GET {shodan_url}", language="bash")
                r = requests.get(shodan_url, timeout=10)
                if r.ok:
                    st.code(r.text, language="json")
                    tool_outputs.append({"tool": "Shodan", "type": "api", "command": shodan_url, "output": r.text})
            except Exception as e:
                st.error(f"Shodan error: {e}")

    if tool_outputs:
        st.subheader("📋 Gemini Summary Report")
        combined = "\n\n".join(
            f"## {entry['tool']}\nCommand: {entry['command']}\nOutput:\n{entry['output']}"
            for entry in tool_outputs
        )
        summary_prompt = f"""
You are a senior OSINT analyst preparing a threat intelligence report based on data collected through a combination of local tools (theHarvester, sherlock, holehe, pwned, socialscan, amass, sublist3r, dnsrecon, waybackurls) and public OSINT APIs (crt.sh, ipinfo.io, shodan.io, AbuseIPDB, viewdns.info).

Produce a detailed and structured report that adapts to the search target type, selecting only relevant sections:

🎯 Target Type: Real Name
1. Executive Summary
Summarise findings and assess likelihood of correlation across platforms.

2. Associated Usernames / Aliases
List usernames or handles linked to this name (sherlock, socialscan).

3. Social Presence
Platforms where accounts were found.

Metadata or location hints if available.

4. Risk Indicators
Evidence of impersonation, identity leakage, credential reuse.

5. Next Steps
Pivot to username, email, or facial/image analysis.

🎯 Target Type: Username
1. Executive Summary
Summary of username presence and OpSec posture.

2. Active Profiles
List of services/accounts with matching usernames (sherlock, socialscan).

3. Credential and Breach Check
Any email reuse identified (holehe, pwned).

4. Behavioural Indicators
Posting habits, tone, timezones, reuse across platforms.

5. Recommendations
Investigate further with email correlation or breach monitoring.

🎯 Target Type: Email Address
1. Executive Summary
Highlight exposure level, compromise status, reuse risk.

2. Breached Accounts
Tools: pwned, holehe.

3. Account Enumeration
Which services the email is registered with (holehe, socialscan).

4. Exposure Level
Public appearance in CT logs (crt.sh), domains registered with it.

5. Recommendations
Password hygiene alert, dark web monitor, possible phishing campaign.

🎯 Target Type: Domain
1. Executive Summary
Domain exposure and digital footprint.

2. Subdomain Discovery
amass, sublist3r, dnsrecon

3. Infrastructure Intel
IPs and ASN (ipinfo.io), CDN, hosting

4. DNS & Certificate Records
crt.sh, viewdns.info, historical lookups

5. Exposure & Risk
Ports & service banners (shodan.io), suspicious activity (AbuseIPDB)

6. Archived URLs
waybackurls for endpoint discovery

7. Recommendations
Identify dev/staging environments, alert on open ports, scan archives for leaks.

🔚 Final Instructions
Structure output in markdown.

Include IOCs (emails, usernames, subdomains, IPs, URLs) in a dedicated table.

Where possible, cross-correlate data (e.g., same IP in Shodan and AbuseIPDB, or domain seen in crt.sh and waybackurls).

Close with a risk rating and tactical next steps for deeper investigation.

{combined}
"""
    try:
        summary_response = model.generate_content(summary_prompt)
        report_md = summary_response.text
        st.session_state['final_report_md'] = report_md
        st.markdown(report_md)
        st.download_button(
            "📄 Download Report as Markdown",
            data=report_md,
            file_name="osint_report.md",
            mime="text/markdown"
        )
    except Exception as e:
        st.error(f"Gemini summary error: {e}")

st.warning("⚠️ Use this tool ethically and legally only.")
