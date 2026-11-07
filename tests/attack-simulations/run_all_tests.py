"""Master runner — all 6 scenarios in order with results table."""
import sys,os,csv,time,importlib
from datetime import datetime
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,BASE_URL

def check():
    status,ms,_=hit("GET","/api/products")
    if status==0: print(f"\n❌ Cannot connect to {BASE_URL} — start the API first\n"); return False
    print(f"✅ API running — {ms}ms\n"); return True

def run_scenario(mod,name):
    print(f"\n{'#'*55}\n  {name}\n{'#'*55}\n")
    m=importlib.import_module(mod)
    return m.run()

def save_csv(results,config="L1+L2+L3+L4"):
    fn=f"results_{config.replace('+','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    with open(fn,'w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=["scenario","total","blocked","allowed","errors","avg_ms","config"])
        w.writeheader()
        for r in results: r["config"]=config; w.writerow(r)
    print(f"\n💾 Saved: {fn}")

def table(results):
    print(f"\n{'='*65}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*65}")
    print(f"  {'Scenario':<32} {'Total':>6} {'Det':>6} {'DR%':>6} {'ms':>7}")
    print(f"  {'-'*58}")
    for r in results:
        total=r['total']; det=r['blocked']
        dr=round(det/total*100,1) if total>0 else 0
        normal="Normal" in r['scenario']
        dr_s="-" if normal else f"{dr}%"
        print(f"  {r['scenario']:<32} {total:>6} {det:>6} {dr_s:>6} {r['avg_ms']:>6}ms")
    print(f"\n  COMPARISON BASELINES:")
    print(f"  {'Tanveer et al. (2025) RESTlogic':<32} {'91.8%':>12} {'3.5% FPR':>12}")
    print(f"  {'Tanveer et al. (2025) range (4 tools)':<32} {'81-92%':>12} {'3.5-6.7% FPR':>12}")
    print(f"  {'This framework (target)':<32} {'≥85%':>12} {'≤10% FPR':>12}")
    print(f"{'='*65}\n")

def main():
    print("\n"+"="*55)
    print("  API SECURITY EVALUATION TEST SUITE")
    print("="*55+"\n")
    if not check(): return
    print("Starting in 3s...\n"); time.sleep(3)
    results=[]
    r=run_scenario("01_normal_traffic","Normal Traffic (Baseline)"); results.append(r)
    log("Waiting 10s before attacks..."); time.sleep(10)
    r=run_scenario("02_credential_stuffing","Credential Stuffing"); results.append(r); time.sleep(5)
    r=run_scenario("03_data_scraping","Data Scraping"); results.append(r); time.sleep(5)
    sys.argv.append("--fast")
    r=run_scenario("04_slow_brute_force","Slow Brute Force (fast)"); results.append(r)
    sys.argv.remove("--fast"); time.sleep(5)
    r=run_scenario("05_bot_flood","Distributed Bot Flood"); results.append(r); time.sleep(5)
    r=run_scenario("06_sql_injection","SQL Injection"); results.append(r); time.sleep(65)
    r=run_scenario("01_normal_traffic","Normal Traffic (Post-Attack FPR)"); results.append(r)
    table(results)
    save_csv(results)
    print("  ✅ Done. Check dashboard Eval Metrics tab for F7-F10.")
    print("  ✅ Export CSV from dashboard for full per-request data.\n")

if __name__=="__main__": main()
