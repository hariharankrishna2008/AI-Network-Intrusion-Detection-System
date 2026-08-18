# AI-Powered Network Intrusion Detection System

**Katy CyberWise Club · Project 1**

A real, runnable system that watches network traffic, decides in real time whether each connection looks suspicious, and streams the verdicts to a live dashboard. It uses two different machine learning models that check each other's work, and it comes with a full evaluation pipeline so you can *prove*, with charts and numbers, how well it actually works.

This project was built collaboratively by a small team from the Katy CyberWise Club, including myself. I contributed significantly to the code and design, but it was very much a group effort — credit goes to everyone who worked on it.

---

## Table of Contents

1. [What problem is this solving?](#what-problem-is-this-solving)
2. [The big picture](#the-big-picture)
3. [Step 1: Turning raw traffic into numbers (feature engineering)](#step-1-turning-raw-traffic-into-numbers-feature-engineering)
4. [Step 2: The two brains — Isolation Forest and Random Forest](#step-2-the-two-brains--isolation-forest-and-random-forest)
5. [Step 3: Scoring a flow in real time](#step-3-scoring-a-flow-in-real-time)
6. [Step 4: The live dashboard](#step-4-the-live-dashboard)
7. [Step 5: Real traffic capture (Scapy)](#step-5-real-traffic-capture-scapy)
8. [Step 6: Alerting](#step-6-alerting)
9. [Step 7: Proving it works (evaluation)](#step-7-proving-it-works-evaluation)
10. [Project structure](#project-structure)
11. [Running it yourself](#running-it-yourself)
12. [Why two models instead of one?](#why-two-models-instead-of-one)
13. [Limitations & honesty section](#limitations--honesty-section)

---

## What problem is this solving?

Every device on a network is constantly sending and receiving traffic — checking email, loading web pages, streaming video. An **Intrusion Detection System (IDS)** is software that watches that traffic and tries to answer one question, over and over, thousands of times a second: *"does this look normal, or does this look like an attack?"*

Traditional IDS tools do this with hand-written rules ("if this IP sends more than X packets per second, flag it"). Rules like that break the moment an attacker does something the rule-writer didn't think of. This project instead uses **machine learning** — the system studies what *normal* traffic statistically looks like, and anything that deviates far enough from that pattern gets flagged automatically, without a human ever writing a rule for that specific attack.

## The big picture

Here's the whole pipeline, end to end:

```
Real packets (Scapy)  ──┐
                         ├──►  Flow  ──►  Feature vector  ──►  Isolation Forest ──► anomaly? ──► Random Forest ──► "what kind of attack?" ──► Dashboard + Alerts
Synthetic generator  ───┘
```

In plain English:

1. Raw network packets get grouped into **flows** (a "conversation" between two computers).
2. Each flow is converted into a small list of numbers (a **feature vector**) that describes its shape — how big it is, how fast, what port it's using, etc.
3. An **Isolation Forest** model looks at that vector and asks: *"Does this look like normal traffic I've seen before, or is it weird?"* This model has never seen a single labeled attack — it only knows what "normal" looks like, and flags anything that doesn't fit.
4. If something is flagged as weird, a second model — a **Random Forest** — steps in and names the *type* of attack it most resembles (port scan, brute force, data exfiltration, etc.), because this model *was* trained on labeled examples of each attack type.
5. The result streams live to a web dashboard, gets logged to a database, and can optionally trigger a desktop notification or email.

That two-model handoff — one model that says "something's wrong," and a second, more specialized model that says "here's what it probably is" — is the core idea of the whole project.

## Step 1: Turning raw traffic into numbers (feature engineering)

Machine learning models don't understand "a computer talking to another computer." They only understand numbers. So the first job is to describe every network **flow** — one continuous conversation between a source and destination, identified by source IP, destination IP, destination port, and protocol — as a fixed list of numbers. This project uses six:

| Feature | What it means |
|---|---|
| `bytes` | Total data transferred in the flow |
| `packets` | Total number of packets sent |
| `duration` | How long the conversation lasted |
| `mean_pkt_size` | Average bytes per packet (`bytes ÷ packets`) — a stealthy scan sends tiny packets, exfiltration sends huge ones |
| `conn_rate` | Packets per second — attacks like SYN floods and brute-force login attempts fire off packets *fast* |
| `dst_port` | Which port is being targeted — port 22 (SSH) or 3389 (Remote Desktop) behaving oddly is more suspicious than port 443 (normal web traffic) |

This step matters more than people expect. A model is only as good as the features it's given — this is why the same feature-extraction code (`ids/features.py`) is shared by the training script, the live scorer, and the real packet-capture path, so a flow always looks the same to the model no matter where it came from.

## Step 2: The two brains — Isolation Forest and Random Forest

This is the heart of the project, and it's worth explaining from scratch, because both algorithms are built out of the same simple building block: the **decision tree**.

### The building block: decision trees

A decision tree asks a series of yes/no questions to sort data, like a flowchart: *"Is `bytes` > 5000? If yes, is `dst_port` == 22? If yes... "* and so on, until it reaches a decision. A single tree is easy to understand but easy to fool — it can memorize quirks of its training data instead of learning general patterns.

The fix used by both models in this project is to build **many** trees instead of one, and combine their opinions. This is called an **ensemble**, and it's one of the most powerful, reliable ideas in classical machine learning.

### Model 1 — Isolation Forest (unsupervised anomaly detection)

The Isolation Forest is trained on **normal traffic only** — it is never shown a single attack example during training (`train.py`). Its whole idea is delightfully simple:

> To find an outlier in a dataset, keep picking random features and random split points, and see how quickly you can "isolate" a data point all by itself.

Imagine a room full of people sorted by height and shoe size. If you randomly draw lines to split the room in half, over and over, a person of totally average height and shoe size takes *many* splits to separate from the crowd — they're surrounded by similar people. But someone who's 7 feet tall gets isolated in one or two splits, because almost no one is near them. Isolation Forest builds hundreds of these random-split trees (an ensemble again) and measures, on average, *how few splits it takes to isolate each flow*. Flows that get isolated fast are flagged as **anomalies**.

This is powerful because it means the model can flag attack types it has *never seen labeled examples of* — it doesn't need to know what a "brute force attack" is, only that this particular flow doesn't resemble the normal traffic it studied. That's exactly why it's the first line of defense in this pipeline.

The raw "how easily was this isolated" score gets converted into a friendlier 0–1 **suspicion score**, and a threshold decides the cutoff for calling something an anomaly (`ids/model.py`).

### Model 2 — Random Forest (supervised classification)

Once the Isolation Forest flags a flow as anomalous, the Random Forest steps in to answer a harder question: *"Okay, but what kind of attack is this?"* This model is trained differently — it's shown thousands of labeled examples (`train_supervised.py`, `ids/datasets.py`), each one tagged as `normal`, `Port scan`, `SYN flood`, `Data exfiltration`, `Brute force`, or `Beaconing`.

A Random Forest is an ensemble of decision trees too, but with two extra tricks that make it much stronger than a single tree:

1. **Bagging (Bootstrap Aggregating):** each tree is trained on a random, slightly different sample of the training data, so the trees end up learning slightly different things.
2. **Random feature selection:** at each split, each tree is only allowed to consider a random subset of features, which stops every tree from just relying on the single strongest feature and forces them to find different patterns.

Then, to classify a new flow, all the trees vote, and the majority vote wins. Because each tree makes different mistakes, their combined vote is far more accurate and far more resistant to overfitting than any one tree alone. The Random Forest also naturally produces **feature importances** — a ranking of which features it actually relies on to make decisions (see `metrics.txt`: `mean_pkt_size` and `bytes` turned out to matter most).

## Step 3: Scoring a flow in real time

Every incoming flow — whether from the synthetic generator or real captured packets — goes through `process_flow()` in `app.py`:

1. Convert the flow to a feature vector.
2. Isolation Forest scores it → suspicion score + anomaly true/false.
3. If it's anomalous, the Random Forest names the likely attack type.
4. The result is saved to a local SQLite database, published to any connected dashboards, and (if enabled) sent to the alerting system.

## Step 4: The live dashboard

The dashboard (`templates/dashboard.html`) is a single web page that connects to the server over **Server-Sent Events (SSE)** — a lightweight, one-directional streaming connection that lets the server push new events to the browser the instant they happen, without the page needing to refresh or repeatedly ask "anything new?" It shows:

- Running totals of flows analyzed and alerts raised
- A live traffic-volume chart, with windows that contained an alert highlighted
- A breakdown of alerts by attack type
- A scrolling table of the most recent flows, each with its suspicion score and verdict
- Controls to pause the stream, inject a test attack burst, or change the demo speed

## Step 5: Real traffic capture (Scapy)

Everything above can run purely on synthetic data (`ids/generator.py`) so the project works out of the box with no special setup. But `ids/capture.py` provides the real path: it uses **Scapy**, a Python packet-manipulation library, to either replay a `.pcap` capture file or sniff live traffic off a network interface, group the raw packets into flows using the exact same logic as the rest of the pipeline, and POST each one to the running dashboard's `/api/flow` endpoint to be scored just like any other flow.

## Step 6: Alerting

`ids/alerting.py` is off by default so the demo isn't noisy, but can optionally fire a desktop notification and/or an email whenever a flow crosses a configurable suspicion threshold, with a per-source cooldown so a single attack burst doesn't spam 50 notifications in a row. Every alert (notified or not) is written to a plain-text log.

## Step 7: Proving it works (evaluation)

Anyone can claim their model works — `evaluate.py` exists to actually measure it, on a held-out test set neither model was trained on, and produce standard machine-learning evaluation charts:

- **ROC curve** — how well each model separates attacks from normal traffic across every possible threshold
- **Precision–Recall curve** — especially important for security, where attacks are rare and false alarms are costly
- **Confusion matrix** — exactly which attack types the Random Forest confuses with which
- **Feature importance** — what the Random Forest actually pays attention to
- **Per-attack-type recall** — detection rate broken down by attack, for both models
- **Threshold tuning** — how precision, recall, and F1 trade off as the Isolation Forest's alert threshold changes

On the synthetic test set, the headline numbers were:

| Model | ROC-AUC | Avg. Precision |
|---|---|---|
| Random Forest | 1.000 | 1.000 |
| Isolation Forest | 0.977 | 0.975 |

The Random Forest — trained *with* labels — naturally does better, especially on subtler attacks like Data Exfiltration and Brute Force (which the unsupervised Isolation Forest catches less consistently, since those attacks can resemble unusually large or long normal connections). That gap is exactly the point of running both: the Isolation Forest is the always-on, no-labels-needed tripwire, and the Random Forest is the specialist that adds detail once something's already been flagged.

**Important honesty note:** these are strong numbers because they're measured on labeled *synthetic* traffic generated by the same rules the models were trained on, which makes the pipeline fully reproducible. Real network traffic (from something like the NSL-KDD dataset, which the code also supports loading) is messier and noisier, and real-world numbers would be lower — that's expected, not a flaw.

## Project structure

```
app.py               Flask web server — loads models, scores flows, streams the dashboard
evaluate.py           Trains both models on shared data, produces evaluation figures + metrics.txt
test_ids.py           Unit tests for feature extraction, training, and detection quality
train.py              Trains the Isolation Forest on synthetic normal traffic
train_supervised.py   Trains the Random Forest on labeled normal + attack traffic
ids/
  capture.py           Real packet capture / pcap replay via Scapy
  datasets.py          Synthetic + real (NSL-KDD) labeled datasets for the Random Forest
  features.py          Shared feature engineering (flow → numeric vector)
  generator.py          Synthetic normal + attack traffic generator
  model.py              Isolation Forest wrapper (train / score / save / load)
  supervised.py          Random Forest wrapper (train / predict / feature importances)
  alerting.py            Desktop notification / email / log alerting
templates/
  dashboard.html        The live dashboard front end
metrics.txt            Latest evaluation results
requirements.txt        Python dependencies
```

## Running it yourself

```bash
pip install -r requirements.txt
python train.py          # trains and saves the Isolation Forest (model.pkl)
python app.py             # starts the dashboard at http://127.0.0.1:5001
```

To feed it real traffic from a lab environment (needs Scapy):

```bash
python -m ids.capture --pcap lab.pcap --url http://127.0.0.1:5001
sudo python -m ids.capture --iface eth0 --url http://127.0.0.1:5001
```

To generate the full evaluation report and charts:

```bash
python evaluate.py
```

## Why two models instead of one?

This is worth calling out explicitly because it's the most interesting design decision in the project. The two algorithms have opposite strengths:

- **Isolation Forest (unsupervised):** doesn't need labeled attack data, so it can flag genuinely novel, never-seen-before attacks. Downside: it can only say "this is weird," not "this is specifically a brute-force attempt."
- **Random Forest (supervised):** far more accurate and specific *if* the attack resembles something it was trained on. Downside: it's blind to attack types it's never seen labeled examples of.

Chaining them — anomaly detector first, specialist classifier second — gets the best of both: broad, label-free coverage for catching the unknown, and sharp, specific classification for the known.

## Limitations & honesty section

- Traffic is currently either synthetic or replayed from a `.pcap` — this hasn't been battle-tested against a live, hostile network.
- Evaluation numbers reflect performance on synthetic data generated by the same rules used in training; real-world performance would be noisier and lower.
- Six features is a compact, interpretable feature set, but a production IDS would likely track more (TCP flags, inter-packet timing, payload entropy, etc.).
- This is a learning project built by students, meant to demonstrate the core ideas behind ML-based intrusion detection — not a hardened, production-ready security product.
