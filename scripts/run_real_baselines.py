import asyncio
from backend.engines.checks import TransportEngine, DependencyEngine, AuthEngine

async def run_baselines():
    print("Executing Baseline Engines against http://localhost:3000 ...\n")
    
    # 1. Transport Engine
    transport = TransportEngine()
    t_res = transport.check_hsts("http://localhost:3000")
    print(f"[Transport] HSTS Check: {t_res.status} - {getattr(t_res, 'reason', getattr(t_res, 'finding_summary', ''))}")
    
    # 2. Dependency Audit
    dep = DependencyEngine()
    d_res = dep.check_npm_audit("/Users/karan/Documents/sihcopy/target")
    print(f"[Dependency] Audit Check: {d_res.status} - {getattr(d_res, 'reason', getattr(d_res, 'finding_summary', ''))}")
    
    # 3. Client Scope Engine (Cookies / Storage) via AuthEngine
    auth = AuthEngine()
    a_res = auth.check_cookie_flags("http://localhost:3000")
    print(f"[Auth] Cookie Flags Check: {a_res.status} - {getattr(a_res, 'reason', getattr(a_res, 'finding_summary', ''))}")

if __name__ == "__main__":
    asyncio.run(run_baselines())
