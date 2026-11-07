"""SQL injection — large and small payloads. Tests L1 + app regex."""
import time,sys,os
sys.path.insert(0,os.path.dirname(__file__))
from config import hit,log,summary

ATTACK_IP="10.1.0.5"
LARGE=[
    {"username":"admin' OR '1'='1"+"X"*2000,"password":"x"},
    {"username":"' UNION SELECT "+"a,"*50+"a FROM users --"+"X"*1500,"password":"x"},
    {"username":"admin'; DROP TABLE users;--"+"X"*1800,"password":"x"},
]
SMALL=[
    {"username":"admin' OR '1'='1","password":"x"},
    {"username":"' UNION SELECT * FROM users --","password":"x"},
    {"username":"admin'; DROP TABLE users; --","password":"x"},
    {"username":"' OR 1=1 --","password":"x"},
    {"username":"admin'--","password":"x"},
    {"username":"'; EXEC xp_cmdshell('dir'); --","password":"x"},
    {"username":"' OR 'x'='x","password":"' OR 'x'='x"},
    {"username":"1' OR '1'='1","password":"x"},
]
ALL=(LARGE*10)+(SMALL*10)

def run():
    log(f"SQL Injection — {len(ALL)} payloads to {ATTACK_IP}")
    log(f"Large (>1500 bytes): {len(LARGE*10)} — Layer 1 payload z-score")
    log(f"Small (<100 bytes):  {len(SMALL*10)} — application regex\n")
    results=[]; l1c=0; ac=0
    for i,payload in enumerate(ALL):
        status,ms,_=hit("POST","/api/login",payload,ip=ATTACK_IP,is_attack=True)
        results.append({"status":status,"ms":ms})
        if status==403: l1c+=1
        elif status==400: ac+=1
        if(i+1)%30==0: log(f"  {i+1}/{len(ALL)} | L1 blocks:{l1c} App blocks:{ac}")
        time.sleep(2.5)
    s=summary("SQL Injection",results)
    total=len(ALL)
    tp=sum(1 for r in results if r["status"] in[403,400,429])
    dr=round(tp/total*100,1)
    print(f"  L1 catches (403): {l1c}  App catches (400): {ac}")
    print(f"  DR: {dr}%  Target ≥95%  {'✅' if dr>=95 else '❌'}\n")
    return s

if __name__=="__main__": run()
