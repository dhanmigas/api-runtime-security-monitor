"""Slow brute force — spaced login attempts. Use --fast for demo."""
import time,sys,os
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,summary

ATTACK_IP="10.1.0.3"; TOTAL=100
FAST="--fast" in sys.argv; DELAY=2 if FAST else 20

def run():
    mode="FAST (2s)" if FAST else "REALISTIC (20s)"
    log(f"Slow Brute Force — {TOTAL} attempts — {mode}")
    log(f"Rate: 1 req every {DELAY}s = {round(60/DELAY,1)} req/min")
    log("A simple 30/min rule scores 0% on this scenario\n")
    results=[]; first=None
    for i in range(TOTAL):
        status,ms,_=hit("POST","/api/login",
            {"username":"admin","password":f"attempt_{i}"},
            ip=ATTACK_IP,is_attack=True,user_agent="python-requests/2.31.0")
        results.append({"status":status,"ms":ms})
        if status in[403,429] and first is None:
            first=i+1; log(f"  [FIRST DETECTION] Attempt #{i+1}: {status}")
        if(i+1)%10==0:
            afr=sum(1 for r in results if r["status"]==401)/len(results)*100
            d=sum(1 for r in results if r["status"] in[403,429])
            log(f"  {i+1}/{TOTAL} | Auth fail: {afr:.0f}% | Detected: {d}")
        time.sleep(DELAY)
    s=summary("Slow Brute Force",results)
    dr=round(sum(1 for r in results if r["status"] in[403,429])/TOTAL*100,1)
    print(f"  DR: {dr}%  Target ≥70%  {'✅' if dr>=70 else '❌'}")
    print(f"  First detected: #{first or 'never'}\n")
    return s

if __name__=="__main__": run()
