# Test Scripts — API Security Evaluation

## Requirements

Python 3.8+ and the requests library:

```bash
pip install requests
```

---

## Before Running

1. Start the API in Visual Studio (press F5)
2. Open the dashboard at http://localhost:5000/dashboard
3. Delete security.db if it exists (fresh start)
4. Run Normal Traffic in the simulator 3-4 times until all endpoints exit warmup
5. Confirm Baselines tab shows ✓ Approved for all endpoints

---

## Run All Scenarios

```bash
cd TestScripts
python run_all_tests.py
```

This runs all six scenarios in order and saves a results CSV.

---

## Run Individual Scenarios

```bash
python 01_normal_traffic.py        # builds baseline, measures FPR
python 02_credential_stuffing.py   # 200 rapid failed logins
python 03_data_scraping.py         # 300 rapid GET requests
python 04_slow_brute_force.py      # slow attack, use --fast for demo
python 04_slow_brute_force.py --fast
python 05_bot_flood.py             # 50 IPs × 10 requests
python 06_sql_injection.py         # 150 injection payloads
```

---

## Layer Contribution Analysis (Research Question Q3)

Edit appsettings.json, restart the API, and run all scenarios for each config:

| Config | EnableL2 | EnableL3 | EnableL4 |
|--------|----------|----------|----------|
| L1 only | false | false | false |
| L1 + L2 | true | false | false |
| L1 + L2 + L3 | true | true | false |
| All layers | true | true | true |

---

## Where to See Results

- **Dashboard → Eval Metrics**: F7-F10 calculated automatically
- **Dashboard → Security Events**: every request with scores
- **Dashboard → Export CSV**: full data for Excel
- **Console output**: summary per scenario with pass/fail

---

## Files

| File | Purpose |
|------|---------|
| config.py | Shared settings and helper functions |
| 01_normal_traffic.py | 500 legitimate requests — baseline + FPR |
| 02_credential_stuffing.py | 200 rapid failed logins from one IP |
| 03_data_scraping.py | 300 rapid GET requests from one IP |
| 04_slow_brute_force.py | 100 slow login attempts — tests F6 accumulation |
| 05_bot_flood.py | 50 IPs × 10 requests — tests Layer 4 swarm |
| 06_sql_injection.py | 150 injection payloads — tests payload z-score |
| run_all_tests.py | Runs everything and produces summary table |
