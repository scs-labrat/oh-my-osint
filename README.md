
# 🕵️‍♂️ Oh My OSINT – Gemini-Powered Reconnaissance Assistant

A cutting-edge, LLM-assisted OSINT investigation platform built with [Streamlit](https://streamlit.io/) that automates CLI tool selection, execution, and reporting using Google Gemini. Designed for threat analysts, red teamers, and researchers who want fast, intelligent, and reproducible reconnaissance.

![screenshot](docs/screenshot.png)

---

## 🔧 Features

- ✅ **Gemini-Powered Tool Selection**  
  Automatically selects the most relevant OSINT tools and flags based on target type.

- 🛠️ **Integrated CLI Recon Tools**  
  Includes `theHarvester`, `amass`, `sublist3r`, `dnsrecon`, `sherlock`, `holehe`, `pwned-cli`, `socialscan`, `waybackurls`.

- 🌐 **Free API Integrations**  
  Includes crt.sh, ipinfo.io, AbuseIPDB, viewdns.info, and Shodan.

- 🔄 **IP Pivoting**  
  Extracts IPs from results and runs additional infrastructure checks automatically.

- 📄 **Auto-Generated Reports**  
  Uses Gemini to summarise tool outputs into markdown reports with actionable insights.

- 💾 **Downloadable Intelligence Reports**  
  Export reports directly from the UI.

---

## 🚀 Quickstart

### Prerequisites

- Python 3.9+
- [pipx](https://pypa.github.io/pipx/)
- Google Gemini API key
- AbuseIPDB and Shodan API keys (optional but recommended)

### 1. Clone the Repo

```bash
git clone https://github.com/scs-labrat/oh-my-osint.git
cd oh-my-osint
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```


### 3. Create `.env`

```
GOOGLE_API_KEY=your_gemini_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
```

### 4. Launch the App

```bash
streamlit run oh_my_osint_llm_api.py
```

---

## 🧠 Target Types Supported

* Username
* Email
* Domain
* IP address
* Phone number

---

## 🧰 Tool Installation

From the sidebar, click **🛠 Install Tools** to automatically install any missing CLI tools using `pipx`, `apt`, or `go`.

---

## 📦 Directory Structure

```
.
├── oh_my_osint_llm_api.py     # Main Streamlit app
├── .env                       # API keys and environment secrets
├── requirements.txt           # Python dependencies
└── README.md
```

---

## 📝 Example Use Case

1. Input a domain like `example.com`.
2. Let Gemini decide which tools to run.
3. CLI tools and APIs run automatically.
4. IPs found are investigated with Shodan, ipinfo, and AbuseIPDB.
5. Gemini summarises everything into a beautiful Markdown report.
6. Click to download the report for further analysis or sharing.

---

## 🛡️ Ethics & Legal

> ⚠️ This tool is for educational and authorised investigative purposes only. Do not use it against systems you don’t own or have permission to test.

---

## 📣 Acknowledgements

Built by [@scs-labrat](https://github.com/scs-labrat) with inspiration from the OSINT, threat intel, and AI communities.

---

## 📜 License

[MIT License](LICENSE)

```
