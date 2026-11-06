# AI Cyber Threat Detection System: Project Explained

> An AI-based full-stack web application that detects, classifies and responds to cyber threats in real time.
> Repo: https://github.com/vazidmansuri005/cyber-threat-detection (private)

---

## Contents

1. [What the project does](#1-what-the-project-does)
2. [How it maps to the problem statement](#2-how-it-maps-to-the-problem-statement)
3. [Architecture](#3-architecture)
4. [The life of one request (end-to-end walkthrough)](#4-the-life-of-one-request)
5. [Datasets](#5-datasets)
6. [Machine learning in depth](#6-machine-learning-in-depth)
7. [Backend (FastAPI) in depth](#7-backend-fastapi-in-depth)
8. [Database design](#8-database-design)
9. [Real-time layer (WebSockets)](#9-real-time-layer-websockets)
10. [Threat response: the "Protect" step](#10-threat-response-the-protect-step)
11. [Frontend (React dashboard)](#11-frontend-react-dashboard)
12. [Traffic simulator](#12-traffic-simulator)
13. [Testing](#13-testing)
14. [Folder structure (file by file)](#14-folder-structure)
15. [How to run](#15-how-to-run)
16. [Results summary](#16-results-summary)
17. [Limitations and future scope](#17-limitations-and-future-scope)
18. [Likely viva questions and answers](#18-likely-viva-questions-and-answers)

---

## 1. What the project does

Traditional security tools mostly rely on fixed signatures, such as known bad file hashes or known bad IPs. They are slow to react to new attacks and often find problems only after the damage is done.

This system puts **machine learning models in the request path** so every piece of incoming data is scored as it arrives:

- **Network traffic:** each connection record is classified as normal traffic or one of four attack families.
- **URLs:** each URL is classified as benign, phishing or malware.
- **Unknown attacks:** a separate anomaly detector flags traffic that doesn't look like anything normal it has seen.
- **Response:** serious threats automatically block the attacker's IP, and every result shows up on a live dashboard within milliseconds.

---

## 2. How it maps to the problem statement

| Slide requirement | Implementation |
|---|---|
| **1. Detect:** an AI-based system that spots cyber threats | Three scikit-learn models loaded into the API, run on every request |
| **2. Classify:** malware, phishing, intrusion attempts, suspicious network activity | Traffic → `Normal / DoS / Probe / R2L / U2R`; URLs → `Benign / Phishing / Malware`; anomaly → `Anomaly` |
| **3. Act in real time:** flag threats as they occur | FastAPI analyses each event in milliseconds and pushes alerts over a WebSocket to the dashboard instantly |
| **4. Protect:** reduce risk to systems and data | Severity scoring + automatic IP blocking (simulated firewall); later traffic from blocked IPs is dropped |

| "Where they fall short" | How this project addresses it |
|---|---|
| Real-time detection | Every event is scored on arrival, with a live WebSocket feed |
| Threat analysis | Classification into attack families, confidence scores, explainable URL indicators, charts |
| Response to evolving threats | Anomaly detector catches patterns never seen in training; the models can be retrained with one command |

Mapping to the **Tools & Technologies** slide:

| Layer | Slide | Used for |
|---|---|---|
| Frontend | React.js, HTML, CSS, JavaScript | Live dashboard, URL scanner, alerts table, blocklist |
| Backend | FastAPI | REST API, request validation, WebSocket, threat-analysis workflow |
| AI / ML | Scikit-learn, NumPy | Feature engineering, model training, inference |
| Database | MySQL | Logs (events), detection results, alerts, blocklist |

---

## 3. Architecture

```
                    ┌───────────────────────────────┐
                    │      Data sources             │
                    │  • simulator (network flows)  │
                    │  • URL Scanner page (URLs)    │
                    └──────────────┬────────────────┘
                                   │ HTTP POST (JSON)
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                         FastAPI backend                          │
│                                                                  │
│  routers/analyze.py ──► schemas.py (validate input)              │
│          │                                                       │
│          ▼                                                       │
│  services/detector.py ──► ML models (loaded once at startup)     │
│          │                 • traffic_model.joblib                │
│          │                 • anomaly_model.joblib                │
│          │                 • url_model.joblib                    │
│          ▼                                                       │
│  services/response.py ──► severity → alert → auto-block          │
│          │                                                       │
│          ├──────────────► Database (MySQL / SQLite)              │
│          │                events, detections, alerts, blocklist  │
│          ▼                                                       │
│  services/alert_bus.py ──► WebSocket /ws/alerts                  │
└──────────────────────────────────┬───────────────────────────────┘
                                   │ push (JSON)
                                   ▼
                    ┌───────────────────────────────┐
                    │     React dashboard (Vite)    │
                    │  Dashboard · URL Scanner ·    │
                    │  Alerts · Blocklist           │
                    └───────────────────────────────┘
```

**Design principles:**
- **Models are trained offline and served online.** `ml/train.py` produces `.joblib` files, and the API only loads and uses them. Training never slows down live detection.
- **Shared feature code.** The training script and the API import the *same* feature code (`backend/app/ml/`), so a feature can never be computed one way in training and another way in production (a classic ML bug called *training/serving skew*).
- **Layered backend.** Routers handle HTTP, services hold the logic, and the db layer holds storage. Each layer can be tested on its own.

---

## 4. The life of one request

What happens when the simulator sends one network connection record:

1. **Simulator** picks a real row from the NSL-KDD test set (say a `neptune` SYN-flood) and attaches a fake attacker IP `203.0.113.16`:
   ```json
   POST /api/analyze/traffic
   { "source_ip": "203.0.113.16",
     "features": { "duration": 0, "protocol_type": "tcp", "service": "private",
                   "flag": "REJ", "src_bytes": 0, "count": 229, ... 41 features } }
   ```
2. **Validation** (`schemas.py`): Pydantic checks that the IP is a valid IPv4/IPv6 address, that all 41 features are present, and that numeric features really are numbers. Bad input gets an HTTP `422` before it ever reaches the model.
3. **Detection** (`detector.py`):
   - The traffic model returns class probabilities, e.g. `DoS: 1.00`.
   - The anomaly model also scores the record.
   - If the classifier says *Normal* but the anomaly model says *unusual*, the result becomes `Anomaly` (a possible zero-day).
4. **Response** (`response.py`):
   - Is `203.0.113.16` already blocked? If yes, mark the event *dropped* and stop.
   - Otherwise save the **event** and the **detection**.
   - DoS has severity **High**, so create an **alert**, add the IP to the **blocklist** and set the alert status to `blocked`.
5. **Broadcast** (`alert_bus.py`): the alert is pushed as JSON to every open dashboard over the WebSocket.
6. **Response to caller:**
   ```json
   { "label": "DoS", "confidence": 1.0, "is_threat": true, "severity": "High",
     "action": "Source IP 203.0.113.16 added to blocklist", "blocked": true, ... }
   ```
7. **Dashboard:** the alert flashes into the live feed, and the counters and charts refresh.
8. **Next request from the same IP:** it is still analysed and logged, but marked *dropped* with no new alert. This shows the "protect" step working.

All of this takes a few milliseconds per event.

---

## 5. Datasets

### 5.1 NSL-KDD (network intrusion)
- Published by the Canadian Institute for Cybersecurity (Tavallaee et al., 2009) as a cleaned-up version of the KDD Cup '99 dataset.
- Each row is **one network connection** described by **41 features** plus a label.
- **Train:** 125,973 rows (`KDDTrain+`). **Test:** 22,544 rows (`KDDTest+`).
- The test set contains **17 attack types that never appear in training** (verified from the data). This makes it a realistic test of "evolving threats".

**Feature groups (41 total):**

| Group | Examples | What it captures |
|---|---|---|
| Basic | `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes` | The connection itself |
| Content | `num_failed_logins`, `root_shell`, `su_attempted`, `num_file_creations` | Suspicious behaviour inside the session (R2L/U2R) |
| Time-based traffic | `count`, `srv_count`, `serror_rate`, `rerror_rate` | Connections to the same host/service in the last 2 seconds (DoS floods) |
| Host-based traffic | `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate` | Patterns over the last 100 connections (slow scans) |

**Label mapping:** about 40 raw attack names are grouped into 5 classes (`backend/app/ml/traffic.py`):

| Class | Meaning | Example attacks | Train count |
|---|---|---|---|
| Normal | Benign traffic | n/a | 67,343 |
| DoS | Denial of Service: flood a server | neptune, smurf, teardrop, back | 45,927 |
| Probe | Reconnaissance: scanning for weak spots | nmap, portsweep, satan, ipsweep | 11,656 |
| R2L | Remote-to-Local: an outsider gains access | guess_passwd, ftp_write, warezmaster | 995 |
| U2R | User-to-Root: a user escalates to admin | buffer_overflow, rootkit, perl | 52 |

The heavy **class imbalance** (52 U2R vs 67k Normal) is the main ML challenge here.

### 5.2 Malicious URLs
- Source: the public dataset by faizann24 on GitHub. It has about 420,000 URLs labelled `good` / `bad`.
- After cleaning and removing duplicates: **411,247 URLs**, of which 344,800 are benign and 66,447 malicious.
- The dataset has no phishing vs malware split, so a **transparent rule** decides the subtype: if the URL path ends in an executable or archive (`.exe .apk .msi .jar .zip .rar ...`), it is **Malware** delivery; otherwise it is **Phishing**.

---

## 6. Machine learning in depth

All training lives in `ml/train.py`. Run it with `.venv/bin/python ml/train.py` (about 2 minutes).

### 6.1 Network traffic classifier

**Preprocessing pipeline** (scikit-learn `ColumnTransformer`):

| Columns | Transform | Why |
|---|---|---|
| `protocol_type`, `service`, `flag` (text) | `OneHotEncoder(handle_unknown="ignore")` | Models need numbers; unknown categories at prediction time are safely ignored |
| 38 numeric columns | `StandardScaler` | Puts features on the same scale (e.g. `src_bytes` in the millions vs rates between 0 and 1); essential for Logistic Regression |

Preprocessing and model are wrapped in one **`Pipeline`** and saved as one file. The API therefore feeds raw features in, and preprocessing happens automatically and identically every time.

**Model comparison** (all trained on `KDDTrain+`, evaluated on `KDDTest+`):

| Model | Accuracy | Macro F1 | Weighted F1 | Train time |
|---|---|---|---|---|
| **Logistic Regression** ✅ | **0.790** | **0.603** | **0.775** | 8.1 s |
| Decision Tree | 0.740 | 0.509 | 0.696 | 0.9 s |
| Random Forest | 0.738 | 0.468 | 0.691 | 1.7 s |

All three use `class_weight="balanced"`, which makes mistakes on rare classes (R2L, U2R) cost more during training. Without it, the model would almost never predict U2R.

**Why macro F1 is the selection metric:** accuracy is dominated by the big classes (Normal and DoS). Macro F1 averages the F1 of each class equally, so a model that ignores U2R gets punished. For security, missing rare attacks matters.

**Why Logistic Regression won (an interesting result for the viva):** tree models memorise the exact patterns of training attacks. Because `KDDTest+` contains 17 *new* attack types, those memorised rules don't transfer. The simpler linear model learns broader trends, such as "many rejected connections means suspicious", which generalise better to unseen attacks. This is a textbook bias-variance trade-off.

**Per-class results (Logistic Regression):**

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Normal | 0.732 | 0.914 | 0.813 | 9,711 |
| DoS | 0.919 | 0.830 | 0.872 | 7,460 |
| Probe | 0.823 | 0.843 | 0.833 | 2,421 |
| R2L | 0.882 | 0.226 | 0.360 | 2,885 |
| U2R | 0.078 | 0.537 | 0.136 | 67 |

**Confusion matrix** (rows are actual, columns are predicted):

| | Normal | DoS | Probe | R2L | U2R |
|---|---|---|---|---|---|
| **Normal** | 8874 | 416 | 350 | 34 | 37 |
| **DoS** | 1194 | 6195 | 69 | 0 | 2 |
| **Probe** | 205 | 129 | 2042 | 39 | 6 |
| **R2L** | 1828 | 3 | 20 | 652 | 382 |
| **U2R** | 17 | 0 | 0 | 14 | 36 |

**Reading it:**
- DoS and Probe are detected well (above 83% recall).
- R2L is the weak spot: 1,828 R2L attacks look like Normal. These attacks (e.g. password guessing) behave much like normal logins at the connection level, and the test set adds new R2L variants.
- U2R is rare (52 training samples), so precision is low, but over half are still caught.
- This weakness is **why the anomaly detector exists** (next section).

### 6.2 Anomaly detector (catches "evolving" threats)

- **Algorithm:** `IsolationForest`, trained **only on Normal traffic**. It learns what "normal" looks like and isolates anything unusual. It never needs attack labels, so it can flag attack types nobody has seen yet.
- **How it works:** it builds random trees that split the data. Unusual points get isolated in very few splits, while normal points need many. Short isolation paths mean an anomaly.
- **Results on `KDDTest+`:**
  - Attack detection rate: **62.7%** of all attacks flagged
  - False positive rate: **2.3%** of normal traffic wrongly flagged
- **How it is combined:** if the classifier says *Normal* but the anomaly detector says *unusual*, the event becomes an `Anomaly` alert (severity Low). This is a second safety net for attacks the classifier misses.

### 6.3 Malicious URL classifier

Two kinds of features are combined in one pipeline:

**a) Character n-grams (TF-IDF)**
- The URL is split into overlapping chunks of 3 to 5 characters: `paypal-login.tk` gives `pay`, `ayp`, `ypa`, ..., `-log`, `login`, `.tk`, and so on.
- **TF-IDF** weights chunks that are distinctive (common in bad URLs, rare overall).
- This automatically learns patterns such as brand names next to odd domains, random-looking strings, and suspicious TLDs, with no hand-written rules needed.
- Settings: `analyzer="char_wb"`, `ngram_range=(3,5)`, `max_features=200,000`, `sublinear_tf=True`.

**b) 17 hand-crafted lexical features** (`backend/app/ml/url_features.py`). These are explainable and shown to the user as "indicators":

| Feature | Why it matters |
|---|---|
| `url_length`, `host_length`, `path_length` | Phishing URLs are often very long to hide the real domain |
| `num_dots`, `num_subdomains` | `paypal.com.secure-login.evil.tk` uses subdomains to imitate a brand |
| `num_hyphens` | `secure-bank-login` style domains |
| `num_at` | `@` makes browsers ignore everything before it (hides the real host) |
| `num_question`, `num_equals` | Heavy query strings, tracking or redirect parameters |
| `num_slashes` | Deep paths |
| `digit_ratio` | Random or generated domains |
| `has_ip_host` | A raw IP instead of a domain is a strong phishing signal |
| `has_https` | Presence of TLS |
| `suspicious_word_count` | login, verify, account, bank, password, paypal, wallet... |
| `has_suspicious_tld` | `.tk .ml .ga .xyz .top .ru` and similar, often abused because they are free or cheap |
| `has_executable_ext` | `.exe .apk .msi ...` indicate malware delivery |
| `entropy` | Shannon entropy; randomness suggests a machine-generated domain |

**Model:** `LogisticRegression(C=5, class_weight="balanced")` on both feature sets together. It is fast, handles 200k sparse features easily, and returns calibrated probabilities that serve as the confidence score.

**Results** (80/20 stratified split, 82,250 test URLs):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| Benign | 0.993 | 0.988 | 0.991 |
| Malicious | 0.941 | 0.964 | 0.952 |

**Accuracy 98.4%, macro F1 0.971.** It catches 96.4% of malicious URLs, with 809 false alarms out of about 69k benign URLs.

### 6.4 Saved artefacts

| File | Size | Contents |
|---|---|---|
| `ml/models/traffic_model.joblib` | 12 KB | Preprocessing + Logistic Regression |
| `ml/models/anomaly_model.joblib` | 1.4 MB | Preprocessing + IsolationForest |
| `ml/models/url_model.joblib` | 3.4 MB | TF-IDF + lexical features + Logistic Regression |
| `ml/models/metrics.json` | n/a | Every metric above, machine-readable |
| `docs/model_report.md` | n/a | Human-readable report (auto-generated) |

---

## 7. Backend (FastAPI) in depth

### 7.1 Startup (`app/main.py`)
FastAPI's **lifespan** hook runs once when the server starts:
1. Reads settings (`config.py`, from env vars or `backend/.env`).
2. Connects to the database and creates any missing tables.
3. Loads all three models into memory, done once instead of per request, which is what makes detection fast.
4. Creates the WebSocket broadcaster.

CORS is restricted to the dashboard origin (`localhost:5173`), so other websites can't call the API from a browser.

### 7.2 Configuration (`app/config.py`)

| Setting | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | SQLite file `backend/threats.db` | Set to `mysql+pymysql://user:pass@host/threatdb` for MySQL |
| `MODELS_DIR` | `ml/models` | Where the `.joblib` files are |
| `CORS_ORIGINS` | `localhost:5173` | Allowed frontend origins |
| `AUTO_BLOCK_ENABLED` | `true` | Turn automatic IP blocking on or off |

No secrets are hard-coded; database credentials come from the environment.

### 7.3 Input validation (`app/schemas.py`)
- **IP addresses** are validated with Python's `ipaddress` module (IPv4 and IPv6).
- **Traffic:** all 41 features must be present; numeric ones must parse as numbers; text ones are length-capped.
- **URLs:** 3 to 2048 characters, no whitespace.
- **Enums:** severity, status and source filters only accept known values.

Invalid requests get `422 Unprocessable Entity` with a clear message and never reach the models or the database.

### 7.4 API reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze/traffic` | Classify one network connection |
| `POST` | `/api/analyze/url` | Classify one URL |
| `GET` | `/api/alerts` | List alerts; filters `severity`, `status`, `source`, `limit` (max 500) |
| `PATCH` | `/api/alerts/{id}` | Update status: `open` / `blocked` / `resolved` |
| `GET` | `/api/stats` | Totals, detection rate, threats by type, by severity, per-minute timeline |
| `GET` | `/api/blocklist` | List blocked IPs |
| `POST` | `/api/blocklist` | Manually block an IP (`409` if already blocked) |
| `DELETE` | `/api/blocklist/{ip}` | Unblock an IP |
| `GET` | `/api/health` | Health check + number of live dashboard connections |
| `WS` | `/ws/alerts` | Live stream of alerts and events |

Interactive Swagger docs are generated automatically at **http://127.0.0.1:8000/docs**.

**Example: URL analysis**
```http
POST /api/analyze/url
{"url": "paypal.com.verify-account-login.tk/webscr/signin.php"}
```
```json
{
  "event_id": 42,
  "source": "url",
  "label": "Phishing",
  "description": "Likely phishing / credential-theft URL",
  "confidence": 1.0,
  "is_threat": true,
  "severity": "High",
  "alert_id": 17,
  "action": "Flagged for analyst review",
  "blocked": false,
  "indicators": {
    "url_length": 52, "host_length": 34, "path_length": 18, "num_dots": 4,
    "num_hyphens": 2, "num_slashes": 2, "num_subdomains": 2,
    "suspicious_word_count": 6, "has_suspicious_tld": 1, "entropy": 4.4022
  }
}
```

---

## 8. Database design

Four tables. The backend creates them automatically through SQLAlchemy, and `docs/mysql_schema.sql` has the equivalent MySQL DDL.

```
events 1 ──── 1 detections 1 ──── 0..1 alerts          blocklist
(raw input)     (model output)        (only for threats)  (blocked IPs)
```

| Table | Key columns | Purpose |
|---|---|---|
| **events** | `id, source (traffic/url), source_ip, payload, dropped, created_at` | Log of **everything** analysed; `payload` stores the raw features (JSON) or URL |
| **detections** | `id, event_id, model, label, confidence, is_threat, anomaly, created_at` | What the model decided for each event |
| **alerts** | `id, detection_id, severity, status, action, created_at` | Created **only for threats**; drives the dashboard and the response workflow |
| **blocklist** | `id, ip (unique), reason, created_at` | The simulated firewall |

**Why three tables instead of one:**
- **events** is a pure audit log, useful for forensics and for retraining.
- **detections** separates *what happened* from *what the AI thought*. You can re-run a newer model on old events.
- **alerts** has its own lifecycle (open → blocked → resolved) that analysts work through.

Indexes are on the columns used for filtering and charts (`label`, `severity`, `status`, `created_at`, `source_ip`).

**MySQL vs SQLite:** the code uses SQLAlchemy, which works with both. SQLite is the zero-setup default for development and demos. Pointing `DATABASE_URL` at MySQL switches the whole app without code changes.

---

## 9. Real-time layer (WebSockets)

**Why WebSockets:** with plain HTTP the dashboard would need to keep asking "anything new?" (polling). A WebSocket keeps one connection open, and the **server pushes** each alert the moment it happens.

**Server** (`services/alert_bus.py`):
- Keeps the set of connected dashboards.
- `publish()` sends a JSON message to every connected dashboard and quietly removes any that have disconnected.
- Two message types:
  - `{"type": "alert", "data": {...}}`: a new alert (shown in the live feed)
  - `{"type": "event", "data": {...}}`: any analysed event (used to trigger table refreshes)

**Client** (`frontend/src/hooks/useLiveFeed.js`):
- Connects to `ws://127.0.0.1:8000/ws/alerts`.
- Keeps the newest 50 alerts in memory.
- **Auto-reconnects** every 2 seconds if the backend restarts.
- Shows a `● LIVE` / `○ offline` indicator in the header.

---

## 10. Threat response: the "Protect" step

Logic lives in `backend/app/services/response.py`.

**Severity mapping:**

| Threat | Severity | Reason |
|---|---|---|
| U2R (privilege escalation) | **Critical** | Attacker gets root, so the system is fully compromised |
| Malware URL | **Critical** | Direct malware delivery |
| R2L (remote intrusion) | **High** | Unauthorised access |
| DoS | **High** | Service outage |
| Phishing URL | **High** | Credential theft |
| Probe (scan) | **Medium** | Reconnaissance, usually a precursor to an attack |
| Anomaly | **Low** | Unusual but unconfirmed |

**Automatic actions:**

| Situation | Action | Alert status |
|---|---|---|
| High/Critical threat **with** a source IP | IP added to blocklist | `blocked` |
| High/Critical threat **without** an IP | "Flagged for analyst review" | `open` |
| Medium/Low threat | "Logged for monitoring" | `open` |
| Any request from an **already-blocked** IP | Logged as `dropped`, **no new alert** (prevents alert floods) | n/a |

Analysts can then **resolve** alerts or **unblock** IPs from the dashboard.

In the 600-event demo run, the system blocked attacker IPs after their first serious attack, and later traffic from them was dropped. That is the "reduce risk" goal working.

---

## 11. Frontend (React dashboard)

Built with **React 18 + Vite**, charts with **Recharts**, plain **CSS** (dark security-operations-centre theme, responsive down to mobile width).

| Page | What it shows |
|---|---|
| **Dashboard** | 6 stat cards (events analysed, threats, detection rate, open alerts, blocked IPs, dropped requests) · area chart of events vs threats per minute · bar chart of threats by type · donut chart of alerts by severity · **live threat feed** with new alerts flashing in |
| **URL Scanner** | Paste a URL to get a verdict (Benign/Phishing/Malware), severity, confidence, automatic response and **human-readable indicators** ("Raw IP address instead of a domain", "Suspicious keywords..."). Includes 3 one-click examples |
| **Alerts** | Full alert history table with filters (severity / status / source), confidence, action taken and a **Resolve** button. Refreshes live |
| **Blocklist** | All blocked IPs with reason and time; manual **Block** form and **Unblock** buttons |

**Code layout:**

| File | Role |
|---|---|
| `src/api.js` | All REST calls in one place; surfaces backend validation errors |
| `src/hooks/useLiveFeed.js` | WebSocket subscription + auto-reconnect |
| `src/components/ui.jsx` | Shared bits: severity badge, status badge, stat card, error note |
| `src/pages/*.jsx` | One file per page |
| `src/App.jsx` | Header, tab navigation, live indicator |

The API address comes from `VITE_API_URL` (see `frontend/.env.example`) instead of being hard-coded.

---

## 12. Traffic simulator

`simulator/replay_traffic.py` turns a static dataset into a **live stream** so the system can be demonstrated in real time:

- Picks random **real** rows from `KDDTest+` (data the model never trained on) and real URLs.
- Assigns **attacker IPs** (`203.0.113.10` to `.39`, a reserved documentation range) to attack rows and random **internal IPs** (`10.0.x.x`) to normal rows. Because attackers come from a small pool, repeat offenders get blocked, and later requests from them show up as *dropped*.
- About 25% of events are URLs and 75% network flows (configurable).
- Prints every threat it triggers to the console.

```bash
.venv/bin/python simulator/replay_traffic.py --rate 2 --count 0   # 2 events/s, forever
#   --rate N       events per second
#   --count N      total events (0 = run until Ctrl+C)
#   --url-share F  fraction of URL events (default 0.25)
#   --seed N       reproducible run
```

---

## 13. Testing

**27 automated tests, all passing** (`cd backend && ../.venv/bin/python -m pytest -q`).

| File | Type | What it covers |
|---|---|---|
| `tests/test_unit.py` | Unit | URL feature extraction (IP hosts, HTTPS, keywords, garbage input), malware vs phishing subtype rule, attack-name → category mapping, severity and auto-block rules |
| `tests/test_api.py` | Integration (real models + real temporary DB) | Health check · DoS traffic → alert + auto-block, **then the same IP is dropped** · normal traffic not flagged · missing features rejected · invalid IP rejected · phishing URL detected with indicators · benign URL passes · stats + alert resolve + 404 · manual block / duplicate 409 / unblock / 404 · **WebSocket receives the live alert** |

Each integration test uses its own fresh temporary SQLite database, so tests never interfere with each other or with real data.

**End-to-end check:** with the API running, 120 simulated events produced 53 threats, 29 auto-blocked IPs and 23 dropped requests. A later 600-event run drove the live dashboard.

---

## 14. Folder structure

```
cyber-threat-detection/
├── README.md                     quick start
├── backend/
│   ├── requirements.txt          pinned Python dependencies
│   ├── .env.example              DATABASE_URL / AUTO_BLOCK_ENABLED template
│   ├── app/
│   │   ├── main.py               FastAPI app, CORS, startup, health
│   │   ├── config.py             settings from env
│   │   ├── schemas.py            request/response validation
│   │   ├── ml/
│   │   │   ├── traffic.py        41 NSL-KDD columns, attack → class map
│   │   │   └── url_features.py   17 lexical URL features + subtype rule
│   │   ├── services/
│   │   │   ├── detector.py       loads models, makes predictions
│   │   │   ├── response.py       severity, alerts, auto-block, persistence
│   │   │   └── alert_bus.py      WebSocket broadcaster
│   │   ├── routers/
│   │   │   ├── analyze.py        POST /api/analyze/traffic|url
│   │   │   ├── alerts.py         alerts, stats, /ws/alerts
│   │   │   └── blocklist.py      blocklist CRUD
│   │   └── db/
│   │       ├── session.py        SQLAlchemy engine/session
│   │       └── models.py         4 tables
│   └── tests/                    27 pytest tests
├── ml/
│   ├── train.py                  trains + compares + saves models, writes report
│   ├── data/                     datasets (downloaded, not in git)
│   └── models/                   .joblib models (generated, not in git) + metrics.json
├── simulator/replay_traffic.py   live traffic generator
├── frontend/                     React + Vite dashboard
│   └── src/ (api.js, App.jsx, hooks/, components/, pages/, styles.css)
├── scripts/
│   ├── setup.sh                  one-shot setup
│   └── download_data.sh          fetch datasets
└── docs/
    ├── model_report.md           auto-generated evaluation
    ├── mysql_schema.sql          MySQL DDL
    └── PROJECT_EXPLAINED.md      this document
```

---

## 15. How to run

**Prerequisites:** Python 3.10+, Node 18+. MySQL is optional.

**First-time setup** (creates the venv, installs dependencies, downloads the datasets, trains the models, installs frontend packages):
```bash
git clone https://github.com/vazidmansuri005/cyber-threat-detection.git
cd cyber-threat-detection
./scripts/setup.sh
```

**Run** (3 terminals):
```bash
# 1  API      → http://127.0.0.1:8000/docs
cd backend && ../.venv/bin/uvicorn app.main:app --reload

# 2  Dashboard → http://localhost:5173
cd frontend && npm run dev

# 3  Live traffic
.venv/bin/python simulator/replay_traffic.py --rate 2 --count 0
```

**Switch to MySQL:**
```bash
brew install mysql && brew services start mysql
mysql -u root < docs/mysql_schema.sql
echo 'DATABASE_URL=mysql+pymysql://threat_user:change-me@localhost:3306/threatdb' > backend/.env
```

**Demo script** (about 5 minutes for a presentation):
1. Open the dashboard. It shows `● LIVE` with empty counters.
2. Start the simulator. Alerts flash into the feed and the charts grow.
3. Point out a **DoS** alert whose status is `blocked`, then the **Dropped requests** counter rising as that attacker retries.
4. Go to **URL Scanner** and click the three examples: Benign, then Phishing (High), then Malware (Critical). Walk through the indicators.
5. Go to **Alerts**, filter to Critical, and resolve one.
6. Go to **Blocklist** and show the auto-blocked IPs; unblock one.
7. Show `docs/model_report.md` and explain the model comparison.

---

## 16. Results summary

| Component | Metric | Value |
|---|---|---|
| Traffic classifier (LogReg) | Accuracy on KDDTest+ (incl. 17 unseen attack types) | **79.0%** |
| | Macro F1 | 0.603 |
| | DoS / Probe recall | 83.0% / 84.3% |
| Anomaly detector | Attacks flagged / false-positive rate | **62.7% / 2.3%** |
| URL classifier | Accuracy / macro F1 | **98.4% / 0.971** |
| | Malicious recall | 96.4% |
| System | Automated tests | 27 / 27 passing |
| | Latency per event | A few milliseconds (in-memory models) |

For context, published classical-ML results on the harder `KDDTest+` split commonly fall around 75–82% accuracy, so 79% is in the expected range.

---

## 17. Limitations and future scope

| Limitation | Future improvement |
|---|---|
| Traffic is **replayed** from a dataset, not captured live | Capture live packets with scapy or CICFlowMeter and compute the same features |
| NSL-KDD is from 1999-era traffic | Retrain on modern datasets (CIC-IDS2017, UNSW-NB15, CSE-CIC-IDS2018) |
| R2L / U2R recall is low (few training samples) | Oversampling (SMOTE), cost-sensitive learning, more data |
| Phishing vs malware is split by a **rule** | Train on a multi-class URL dataset |
| Blocking is **simulated** in the database | Push rules to a real firewall (iptables, pfSense, cloud WAF) |
| No login on the dashboard | JWT authentication + role-based access + rate limiting |
| Classical ML models | Deep learning (LSTM/CNN on flows, CNN on URL characters), online/continuous learning |
| Single server | Message queue (Kafka) for high-volume streams, Docker deployment |

---

## 18. Likely viva questions and answers

**Q: Why machine learning instead of signature rules?**
Signatures only match attacks already known. ML learns the *behaviour* of attacks, so it can catch variants. The anomaly detector goes further and flags anything unusual, even an attack type never seen before.

**Q: Why did Logistic Regression beat Random Forest?**
The test set contains 17 attack types absent from training. Random Forest memorises the specific training attacks (overfitting), while Logistic Regression learns simpler, broader patterns that transfer to new attacks. It is the bias-variance trade-off.

**Q: Why macro F1 and not accuracy?**
The classes are very imbalanced (67k Normal vs 52 U2R). A model that never predicts U2R could still score high accuracy. Macro F1 gives every class equal weight, so rare but dangerous attacks count.

**Q: How do you handle class imbalance?**
With `class_weight="balanced"`, which makes errors on rare classes cost more during training, and by selecting the model on macro F1.

**Q: What is IsolationForest and why use it?**
It is an unsupervised anomaly detector trained only on normal traffic. Anomalies are easy to isolate with random splits, so they have short paths in the trees. It catches 62.7% of attacks with only 2.3% false alarms and needs no attack labels, which suits zero-day threats.

**Q: How does the URL model work?**
It combines TF-IDF character 3–5-grams (automatically learned patterns) with 17 explainable lexical features (IP host, suspicious words, TLD, entropy and more), fed into Logistic Regression. It reaches 98.4% accuracy.

**Q: What does "real time" mean in your system?**
Each event is scored the moment it arrives (models are already in memory, a few ms per event), and alerts are pushed to the dashboard over a WebSocket instead of waiting for a refresh.

**Q: How does the system protect?**
High and Critical threats automatically add the source IP to the blocklist. Later requests from that IP are dropped without creating new alerts. Analysts can review, resolve and unblock from the dashboard.

**Q: Why FastAPI?**
It is Python (the same language as the ML stack, so models load directly), async (good for WebSockets), validates input automatically with Pydantic, and generates Swagger docs for free.

**Q: Why store events, detections and alerts separately?**
Separation of concerns: events are an audit log (also useful for retraining), detections are model outputs (re-runnable with newer models), and alerts have their own analyst workflow (open, blocked, resolved).

**Q: What is training/serving skew and how did you avoid it?**
It happens when features are computed differently in training and in production. Here the training script and the API import the exact same feature code, and preprocessing is saved inside the model pipeline.

**Q: How is input validated and the app kept safe?**
Pydantic schemas validate every field (IP format, all 41 features, numeric types, URL length). CORS is limited to the dashboard origin, there are no hard-coded secrets (DB credentials come from env vars), and SQLAlchemy uses parameterised queries, which prevents SQL injection.

**Q: What would you do with more time?**
Live packet capture, newer datasets, deep-learning models, real firewall integration, authentication and Docker deployment.
