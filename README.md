# Developer-Governed Runtime API Security Monitoring Framework

ASP.NET Core middleware that learns what normal traffic looks like for each API endpoint, then scores every request against that baseline and decides whether to **allow, log, rate-limit or block** it. It uses no machine learning: every decision comes from transparent statistics and rules that a developer can read, tune and approve.

Built as my MSc Applied Cybersecurity dissertation at Technological University Dublin (supervisor: Prof. Mark O'Neill).

## Why "developer-governed"?
Most anomaly detectors adapt silently. In this framework, a new or changed baseline is only a **proposal**. An endpoint stays unscored until a developer approves its initial baseline on the dashboard (human-in-the-loop), so the system never starts blocking on numbers nobody has checked.

## How it works

```
Request ─► SecurityMiddleware
             │
             ├─ L1  Endpoint baseline (z-scores): request frequency (per IP and aggregate),
             │      payload size, auth-failure rate, error rate
             ├─ L2  Per-IP behaviour: request volume, auth-failure count/rate, prior blocks
             ├─ L3  Bot signals: missing User-Agent, machine-regular timing,
             │      invalid sessions, repetitive endpoint sequences
             └─ L4  Distributed/swarm signals: many IPs on one endpoint in 60 s,
                    shared subnets, near-identical payloads
             │
             ▼
     Weighted risk score (0–1) ─► Decision
        < 0.30 Allow · < 0.60 Log · < 0.85 Rate-limit (429) · ≥ 0.85 Block (403)
```

Layers 2–4 can be switched on or off in `appsettings.json` to measure how much each one contributes.

| Folder | Contents |
|---|---|
| `src/ApiSecurityDemo/` | .NET 10 middleware, SQLite event store, demo API and live dashboard |
| `tests/attack-simulations/` | Python traffic generators for normal use and five attack types |
| `results/runs/` | CSV output from each evaluation run during tuning (Jul–Aug 2026) |

## Results

All four layers, mean of three independent runs (each with a fresh database, warm-up and baseline approval):

| Metric | Result | Target |
|---|---|---|
| Overall detection rate | **99.97%** | ≥ 85% |
| False positive rate (legitimate requests rate-limited or blocked) | **0.0%** | ≤ 10% |
| Precision | **100%** | ≥ 80% |
| F1-score | **1.000** | ≥ 0.82 |
| Average middleware latency | **3.76 ms** | ≤ 5 ms |

| Scenario | Detection rate |
|---|---|
| Credential stuffing | 98.0% |
| Data scraping | 96.0% |
| Slow brute force | 90.0% |
| Distributed bot flood | 86.3% |
| SQL injection | 90.9%* |

\*A scoring-script undercount: `summary()` in `config.py` ignores HTTP 400, so the 10 payloads caught by the regex check were not counted. Raw request data shows all 110 payloads detected.

**Why four layers?** With the baseline layer (L1) alone, detection is close to 100%, but **60.1% of legitimate requests are blocked or rate-limited**. Adding the behavioural layers brings that to 0%. No partial configuration covers every attack: per-IP signals alone miss distributed bot floods (0%), and swarm signals alone miss single-source attacks.

**Human-in-the-loop in practice:** during testing, the scraping scenario made the engine propose raising GET /api/products' normal request rate by 122%. The proposal waited for approval and was rejected, so test traffic never became the new "normal".

`results/runs/` holds the per-scenario CSV output from the test scripts during development (Jul–Aug 2026). These count only 403/429 responses as blocked, so they don't match the dashboard metrics above exactly.

## Run it

**Requirements:** .NET 10 SDK, Python 3.8+ with `requests`.

```bash
# 1. Start the API and dashboard
cd src/ApiSecurityDemo
dotnet run
# Dashboard: http://localhost:5000/dashboard

# 2. In a second terminal, run the attack simulations
cd tests/attack-simulations
pip install requests
python run_all_tests.py
```

Run normal traffic first until every endpoint has left warm-up, then approve the baselines on the dashboard. `tests/attack-simulations/README.md` has the full procedure and the layer-comparison setup.

## Limitations
This is a research prototype, not a production product.
- For testing, the client IP is read from the `X-Simulated-IP` and `X-Forwarded-For` headers. In production it must come only from a trusted proxy, because clients can spoof these headers.
- State is held in memory and in a local SQLite file, so it runs on one instance only.
- Thresholds were tuned on simulated traffic and would need re-tuning on real traffic.

## Contributing
Ideas are welcome, especially on integrating baseline approval into CI/CD pipelines. Please open an issue.

## Licence
MIT. See [LICENSE](LICENSE).
