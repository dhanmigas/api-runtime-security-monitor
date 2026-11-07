"""Credential stuffing — 200 rapid failed logins from one IP."""
import time,random,sys,os
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,summary

ATTACK_IP="10.1.0.1"; TOTAL=200; DELAY=0.05
USERS=["admin","administrator","user","root","test","john.smith","jane.doe"]
PASSWORDS=[f"password{i}" for i in range(50)]+["123456","qwerty","letmein","welcome","monkey"]

def run():
    log(f"Credential Stuffing — {TOTAL} attempts from {ATTACK_IP}")
    log(f"Rate: ~{round(1000/DELAY/60*60)} req/min\n")
    results=[]; first=None
    for i in range(TOTAL):
        status,ms,_=hit("POST","/api/login",
            {"username":random.choice(USERS),"password":random.choice(PASSWORDS)},
            ip=ATTACK_IP,is_attack=True)
        results.append({"status":status,"ms":ms})
        if status in[403,429] and first is None:
            first=i+1; log(f"  [DETECTED] Attempt #{i+1}: {status}")
        if(i+1)%50==0:
            d=sum(1 for r in results if r["status"] in[403,429])
            log(f"  {i+1}/{TOTAL} | Detected: {d}")
        time.sleep(DELAY)
    s=summary("Credential Stuffing",results)
    tp=sum(1 for r in results if r["status"] in[403,429])
    dr=round(tp/TOTAL*100,1)
    print(f"  DR: {dr}%  Target ≥85%  {'✅' if dr>=85 else '❌'}")
    print(f"  First detected: attempt #{first or 'never'}\n")
    return s

if __name__=="__main__": run()
