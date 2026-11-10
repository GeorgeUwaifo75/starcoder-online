import os, time, uuid, hashlib, secrets, asyncio
import httpx
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

E = os.getenv
API_BASE = E("JSONBIN_API_BASE", "https://jsonbinbro.onrender.com/api")
BIN_ID, BIN_KEY = E("JSONBIN_BIN_ID"), E("JSONBIN_API_KEY")
PRIVATE = E("JSONBIN_PRIVATE", "true").lower() != "false"
SA_ID = E("SUPER_ADMIN_ID", "superadmin")
SA_PW = E("SUPER_ADMIN_PASSWORD", "SuperAdmin4140#")
SALE_COST, START_UNITS = 20, 100
SYS = {"max_tx": 50000, "copies": 1, "footer": "Thanks for purchasing from us today. Please come back."}
KEYS = {"users": {}, "company": {}, "system": {}, "products": {}, "sales": [], "purchases": [], "misc": [], "deleted": []}

app = FastAPI(title="StarCoder Online")
lock = asyncio.Lock()   # serialises every write -> data integrity (run with ONE worker)
DB, SESS = {}, {}


def now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def hp(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex()
def chk(pw, h): return secrets.compare_digest(hp(pw, h.split("$")[0]), h)
def num(x, d=0):
    try: return float(x)
    except Exception: return d


async def save():
    if not BIN_ID: return
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.put(f"{API_BASE}/bins/{BIN_ID}", params={"api_key": BIN_KEY},
                        json={"data": DB, "name": "StarCoder Online", "is_private": PRIVATE})
        if r.status_code >= 400:
            print("JSONBinBro save failed", r.status_code, r.text)
            raise HTTPException(502, "Storage save failed")


@app.on_event("startup")
async def boot():
    global DB
    d = None
    if BIN_ID:  # refuse to start on a failed load, so we never overwrite real data with an empty DB
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{API_BASE}/bins/{BIN_ID}", params={"api_key": BIN_KEY})
            if r.status_code == 404: d = None          # brand-new bin: start empty
            elif r.status_code >= 400: raise RuntimeError(f"JSONBinBro load failed {r.status_code}: {r.text}")
            else:
                d = r.json()
                d = d.get("data", d) if isinstance(d, dict) else None
    DB = d if d and "users" in d else {}
    for k, v in KEYS.items(): DB.setdefault(k, type(v)())
    if SA_ID not in DB["users"]:
        DB["users"][SA_ID] = {"id": SA_ID, "name": "Super Administrator", "role": "super", "pw": hp(SA_PW),
                              "active": True, "tenant": None, "wallet": 0, "perms": {}}
        await save()


# ---------- auth helpers ----------
def me(authorization: str = Header("")):
    u = DB["users"].get(SESS.get(authorization))
    if not u or not u["active"]: raise HTTPException(401, "Please log in")
    if u["tenant"] and not DB["users"][u["tenant"]]["active"]: raise HTTPException(403, "Account deactivated")
    return u
def can(u, p): return u["role"] == "admin" or bool(u["perms"].get(p))
def admin(u=Depends(me)):
    if u["role"] != "admin": raise HTTPException(403, "Administrators only")
    return u
def sup(u=Depends(me)):
    if u["role"] != "super": raise HTTPException(403, "Super administrator only")
    return u
def stk(u=Depends(me)):
    if u["role"] not in ("admin", "semi"): raise HTTPException(403, "Not permitted")
    return u
def usr(u=Depends(me)):
    if u["role"] == "user" or not can(u, "users"): raise HTTPException(403, "Not permitted")
    return u
def ledger_ok(u=Depends(me)):
    if u["role"] == "user" or not can(u, "reports"): raise HTTPException(403, "Not permitted")
    return u


def info(u):
    t = u["tenant"]; root = DB["users"].get(t)
    return {"user": {k: u[k] for k in ("id", "name", "role", "perms")},
            "company": DB["company"].get(t, {}), "system": DB["system"].get(t, SYS),
            "wallet": root["wallet"] if root else 0,
            "sales_count": sum(1 for s in DB["sales"] if s["tenant"] == t)}


def new_user(first, last, pw, role, tenant, perms=None):
    if not (first and last and pw): raise HTTPException(400, "First name, last name and password are required")
    if len(pw) < 6: raise HTTPException(400, "Password must be at least 6 characters")
    base = (first + "." + last).lower().replace(" ", ""); uid, n = base, 1
    while uid in DB["users"]: n += 1; uid = f"{base}{n}"
    DB["users"][uid] = {"id": uid, "name": f"{first} {last}", "role": role, "pw": hp(pw), "active": True,
                        "tenant": tenant or uid, "wallet": START_UNITS if role == "admin" and not tenant else 0,
                        "perms": perms or {}}
    return uid


@app.post("/api/signup")
async def signup(b: dict):
    f, l, pw, cf, co = [str(b.get(k, "")).strip() for k in ("first", "last", "password", "confirm", "company")]
    if not co: raise HTTPException(400, "Company name is required")
    if pw != cf: raise HTTPException(400, "Passwords do not match")
    async with lock:
        uid = new_user(f, l, pw, "admin", None)
        DB["company"][uid] = {"name": co, "address": "", "phone": "", "email": "", "logo": "", "vat": 0}
        DB["system"][uid] = dict(SYS)
        await save()
    return {"id": uid}


@app.post("/api/login")
async def login(b: dict):
    u = DB["users"].get(str(b.get("id", "")).strip().lower())
    if not u or not chk(str(b.get("password", "")), u["pw"]): raise HTTPException(401, "Invalid user ID or password")
    if not u["active"]: raise HTTPException(403, "Account deactivated")
    if u["tenant"] and not DB["users"][u["tenant"]]["active"]: raise HTTPException(403, "Company account deactivated")
    t = secrets.token_hex(24); SESS[t] = u["id"]
    return {"token": t, **info(u)}


@app.get("/api/me")
def whoami(u=Depends(me)): return info(u)


# ---------- users ----------
@app.get("/api/users")
def users(u=Depends(usr)):
    return [{k: x[k] for k in ("id", "name", "role", "active", "perms")} for x in DB["users"].values() if x["tenant"] == u["tenant"]]


@app.post("/api/users")
async def add_user(b: dict, u=Depends(usr)):
    role = b.get("role")
    if role not in ("admin", "semi", "user"): raise HTTPException(400, "Bad role")
    if role == "admin" and u["role"] != "admin": raise HTTPException(403, "Only administrators can create administrators")
    async with lock:
        uid = new_user(str(b.get("first", "")).strip(), str(b.get("last", "")).strip(), str(b.get("password", "")), role, u["tenant"],
                       {k: bool(b.get("perms", {}).get(k)) for k in ("reports", "users", "delete_last")})
        await save()
    return {"id": uid}


@app.patch("/api/users/{uid}")
async def patch_user(uid: str, b: dict, u=Depends(usr)):
    async with lock:
        x = DB["users"].get(uid)
        if not x or x["tenant"] != u["tenant"] or uid in (u["id"], u["tenant"]): raise HTTPException(404, "Not found")
        if x["role"] == "admin" and u["role"] != "admin": raise HTTPException(403, "Not permitted")
        if "active" in b: x["active"] = bool(b["active"])
        if "perms" in b: x["perms"] = {k: bool(b["perms"].get(k)) for k in ("reports", "users", "delete_last")}
        await save()
    return {"ok": True}


@app.put("/api/users/{uid}")
async def edit_user(uid: str, b: dict, u=Depends(usr)):
    async with lock:
        x = DB["users"].get(uid)
        if not x or x["tenant"] != u["tenant"]: raise HTTPException(404, "Not found")
        if x["role"] == "admin" and u["role"] != "admin": raise HTTPException(403, "Not permitted")
        first, last, pw, role = (str(b.get(k) or "").strip() for k in ("first", "last", "password", "role"))
        if first or last:
            if not (first and last): raise HTTPException(400, "Enter both first and last name")
            x["name"] = f"{first} {last}"
        if pw:
            if len(pw) < 6: raise HTTPException(400, "Password must be at least 6 characters")
            x["pw"] = hp(pw)
            if uid != u["id"]:   # force the edited user to log in again with the new password
                for tok in [k for k, v in SESS.items() if v == uid]: del SESS[tok]
        if role and role != x["role"]:
            if uid in (u["id"], u["tenant"]): raise HTTPException(400, "You cannot change your own role or the main administrator's")
            if role not in ("admin", "semi", "user"): raise HTTPException(400, "Bad role")
            if role == "admin" and u["role"] != "admin": raise HTTPException(403, "Only administrators can make administrators")
            x["role"] = role
        await save()
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def del_user(uid: str, u=Depends(usr)):
    async with lock:
        x = DB["users"].get(uid)
        if not x or x["tenant"] != u["tenant"] or uid in (u["id"], u["tenant"]): raise HTTPException(404, "Not found")
        if x["role"] == "admin" and u["role"] != "admin": raise HTTPException(403, "Not permitted")
        del DB["users"][uid]; await save()
    return {"ok": True}


# ---------- products & purchases ----------
def clean(b, t):
    code, name = str(b.get("code", "")).strip(), str(b.get("name", "")).strip()
    if not code or not name: raise HTTPException(400, "Product code and name are required")
    return {"code": code, "name": name, "desc": b.get("desc") or name, "cost": num(b.get("cost")),
            "ptype": "float" if b.get("ptype") == "float" else "discrete", "price": num(b.get("price")),
            "w1": num(b.get("w1")), "w2": num(b.get("w2")), "discount": num(b.get("discount")),
            "supplier": b.get("supplier", ""), "phone": b.get("phone", ""),
            "min": num(b.get("min"), 5), "max": num(b.get("max"), 20), "image": b.get("image", ""), "tenant": t}


def add_purchase(u, p, qty, cost, supplier):
    p["qty"] = round(p["qty"] + qty, 3)
    DB["purchases"].append({"id": uuid.uuid4().hex[:8], "tenant": u["tenant"], "ts": now(), "by": u["id"], "code": p["code"],
                            "name": p["name"], "qty": qty, "cost": cost, "total": round(qty * cost, 2), "supplier": supplier})


@app.get("/api/products")
def products(u=Depends(me)):
    hide = ("cost", "supplier", "phone") if u["role"] == "user" else ()
    return [{k: v for k, v in p.items() if k not in hide} for p in DB["products"].values() if p["tenant"] == u["tenant"]]


@app.post("/api/products")
async def add_product(b: dict, u=Depends(stk)):
    t = u["tenant"]; p = clean(b, t); key = f"{t}:{p['code']}"
    async with lock:
        if key in DB["products"]: raise HTTPException(400, "Product code already exists")
        p["qty"] = 0; DB["products"][key] = p
        q = num(b.get("qty"))
        if q < 0: raise HTTPException(400, "Quantity cannot be negative")
        if q > 0: add_purchase(u, p, q, p["cost"], p["supplier"])   # new product = new purchase transaction
        await save()
    return p


@app.put("/api/products/{code}")
async def edit_product(code: str, b: dict, u=Depends(stk)):
    t = u["tenant"]
    async with lock:
        old = DB["products"].get(f"{t}:{code}")
        if not old: raise HTTPException(404, "Not found")
        p = clean({**b, "code": code}, t); p["qty"] = old["qty"]; p["image"] = b.get("image") or old.get("image", "")
        DB["products"][f"{t}:{code}"] = p; await save()
    return p


@app.post("/api/purchases")
async def purchase(b: dict, u=Depends(stk)):
    async with lock:
        p = DB["products"].get(f"{u['tenant']}:{b.get('code')}")
        q = num(b.get("qty"))
        if not p or q <= 0: raise HTTPException(400, "Choose a product and a positive quantity")
        if p["ptype"] == "discrete" and q != int(q): raise HTTPException(400, "Whole quantities only for this product")
        c = num(b.get("cost"), p["cost"]); p["cost"] = c
        add_purchase(u, p, q, c, b.get("supplier") or p["supplier"]); await save()
    return {"ok": True}


@app.post("/api/misc")
async def misc(b: dict, u=Depends(stk)):
    if b.get("type") not in ("income", "expense") or num(b.get("amount")) <= 0: raise HTTPException(400, "Invalid entry")
    async with lock:
        DB["misc"].append({"id": uuid.uuid4().hex[:8], "tenant": u["tenant"], "ts": (b.get("date") or now()[:10]) + "T00:00:00Z",
                           "type": b["type"], "amount": num(b["amount"]), "note": b.get("note", ""), "by": u["id"]})
        await save()
    return {"ok": True}


@app.get("/api/deleted")
def deleted_log(u=Depends(admin)): return [x for x in DB["deleted"] if x["tenant"] == u["tenant"]]


@app.get("/api/ledger")
def ledger(u=Depends(ledger_ok)):
    t = u["tenant"]
    return {"purchases": [x for x in DB["purchases"] if x["tenant"] == t], "misc": [x for x in DB["misc"] if x["tenant"] == t]}


# ---------- sales ----------
def log_delete(u, method, restocked, sale=None, summary=None):
    """Audit trail: every deleted transaction is kept, with full sale details, for the administrator."""
    DB["deleted"].append({"id": uuid.uuid4().hex[:8], "tenant": u["tenant"], "ts": now(), "by": u["id"], "by_name": u["name"],
                          "method": method, "restocked": restocked, "sale": sale, "summary": summary})


@app.post("/api/sales")
async def sell(b: dict, u=Depends(me)):
    t = u["tenant"]
    if u["role"] == "super": raise HTTPException(403, "Not permitted")
    pay = b.get("payment", "cash")
    if pay not in ("cash", "card", "transfer"): raise HTTPException(400, "Bad payment type")
    async with lock:
        root = DB["users"][t]
        if root["wallet"] < SALE_COST: raise HTTPException(402, "Insufficient wallet units. Please top up to continue selling.")
        vat = num(DB["company"].get(t, {}).get("vat"))
        items, left, sub = [], {}, 0
        for it in b.get("items", []):
            p = DB["products"].get(f"{t}:{it.get('code')}")
            if not p: raise HTTPException(400, "Unknown product")
            q = num(it.get("qty"))
            if q <= 0 or (p["ptype"] == "discrete" and q != int(q)): raise HTTPException(400, f"Invalid quantity for {p['name']}")
            left[p["code"]] = left.get(p["code"], p["qty"]) - q
            if left[p["code"]] < 0: raise HTTPException(400, f"Insufficient stock: {p['name']}")
            tier = it.get("tier") if it.get("tier") in ("w1", "w2") and p[it.get("tier")] > 0 else "price"
            d = p["discount"] if it.get("disc") and p["discount"] > 0 else 0
            line = round(q * p[tier] * (1 - d / 100), 2); sub += line
            items.append({"code": p["code"], "name": p["name"], "qty": q, "price": p[tier], "disc": d, "line": line, "cost": p["cost"]})
        if not items: raise HTTPException(400, "Cart is empty")
        for c, q in left.items(): DB["products"][f"{t}:{c}"]["qty"] = round(q, 3)
        sub = round(sub, 2); tax = round(sub * vat / 100, 2)
        sale = {"id": uuid.uuid4().hex[:8].upper(), "tenant": t, "seller": u["id"], "seller_name": u["name"], "ts": now(),
                "payment": pay, "items": items, "subtotal": sub, "vat": vat, "tax": tax, "total": round(sub + tax, 2)}
        DB["sales"].append(sale); root["wallet"] -= SALE_COST
        await save()
    return {"sale": sale, "wallet": root["wallet"]}


@app.get("/api/sales")
def sales(u=Depends(me)):
    own = not can(u, "reports")
    return [s for s in DB["sales"] if s["tenant"] == u["tenant"] and (not own or s["seller"] == u["id"])]


@app.delete("/api/sales/last")
async def delete_last(u=Depends(me)):
    if not can(u, "delete_last"): raise HTTPException(403, "Not permitted")
    async with lock:
        mine = [s for s in DB["sales"] if s["tenant"] == u["tenant"] and (u["role"] == "admin" or s["seller"] == u["id"])]
        if not mine: raise HTTPException(404, "No transaction to delete")
        s = mine[-1]
        for i in s["items"]:
            p = DB["products"].get(f"{u['tenant']}:{i['code']}")
            if p: p["qty"] = round(p["qty"] + i["qty"], 3)
        DB["sales"].remove(s); log_delete(u, "last", True, s)
        await save()   # units are never refunded when a transaction is deleted
    return {"deleted": s["id"], "wallet": DB["users"][u["tenant"]]["wallet"]}


@app.post("/api/sales/delete")
async def delete_sales(b: dict, u=Depends(admin)):
    ids, t = set(map(str, b.get("ids", []))), u["tenant"]
    async with lock:
        hit = [s for s in DB["sales"] if s["tenant"] == t and s["id"] in ids]
        if not hit: raise HTTPException(404, "No matching transactions")
        if b.get("restock"):
            for s in hit:
                for i in s["items"]:
                    p = DB["products"].get(f"{t}:{i['code']}")
                    if p: p["qty"] = round(p["qty"] + i["qty"], 3)
        for s in hit: log_delete(u, "selected", bool(b.get("restock")), s)
        DB["sales"] = [s for s in DB["sales"] if not (s["tenant"] == t and s["id"] in ids)]
        await save()
    return {"deleted": len(hit), "wallet": DB["users"][t]["wallet"]}


@app.post("/api/cleanup")
async def cleanup(b: dict, u=Depends(admin)):
    before = str(b.get("before", ""))
    if len(before) != 10: raise HTTPException(400, "Choose a date")
    async with lock:
        gone = [s for s in DB["sales"] if s["tenant"] == u["tenant"] and s["ts"][:10] < before]
        if gone:
            log_delete(u, "cleanup", False, None, {"count": len(gone), "total": round(sum(s["total"] for s in gone), 2), "before": before})
        DB["sales"] = [s for s in DB["sales"] if not (s["tenant"] == u["tenant"] and s["ts"][:10] < before)]
        await save()
    return {"deleted": len(gone)}


# ---------- settings, backup ----------
@app.put("/api/settings")
async def settings(b: dict, u=Depends(admin)):
    t, c, s = u["tenant"], b.get("company", {}), b.get("system", {})
    async with lock:
        DB["company"][t] = {k: str(c.get(k, "")) for k in ("name", "address", "phone", "email", "logo")} | {"vat": max(0, num(c.get("vat")))}
        DB["system"][t] = {"max_tx": int(num(s.get("max_tx"), 50000)), "copies": max(1, int(num(s.get("copies"), 1))),
                           "footer": str(s.get("footer", SYS["footer"]))}
        await save()
    return info(u)


@app.get("/api/backup")
def backup(u=Depends(admin)):
    t = u["tenant"]
    d = {k: [x for x in DB[k] if x["tenant"] == t] for k in ("sales", "purchases", "misc", "deleted")}
    d["products"] = [p for p in DB["products"].values() if p["tenant"] == t]
    d["company"], d["system"] = DB["company"].get(t), DB["system"].get(t)
    return d


@app.post("/api/restore")
async def restore(b: dict, u=Depends(admin)):
    t = u["tenant"]
    async with lock:
        for k in ("sales", "purchases", "misc", "deleted"):
            DB[k] = [x for x in DB[k] if x["tenant"] != t] + [dict(x, tenant=t) for x in b.get(k, [])]
        DB["products"] = {k: v for k, v in DB["products"].items() if v["tenant"] != t}
        for p in b.get("products", []): p["tenant"] = t; DB["products"][f"{t}:{p['code']}"] = p
        if b.get("company"): DB["company"][t] = b["company"]
        if b.get("system"): DB["system"][t] = b["system"]
        await save()
    return {"ok": True}


# ---------- super administrator ----------
@app.get("/api/accounts")
def accounts(u=Depends(sup)):
    return [{"id": x["id"], "name": x["name"], "company": DB["company"].get(x["id"], {}).get("name", ""),
             "wallet": x["wallet"], "active": x["active"]} for x in DB["users"].values() if x["role"] == "admin" and x["tenant"] == x["id"]]


@app.post("/api/accounts/{uid}/active")
async def acc_active(uid: str, b: dict, u=Depends(sup)):
    async with lock:
        x = DB["users"].get(uid)
        if not x or x["role"] != "admin": raise HTTPException(404, "Not found")
        x["active"] = bool(b.get("active")); await save()
    return {"ok": True}


@app.post("/api/accounts/{uid}/topup")
async def topup(uid: str, b: dict, u=Depends(sup)):
    n = int(num(b.get("units")))
    async with lock:
        x = DB["users"].get(uid)
        if not x or x["tenant"] != uid or n <= 0: raise HTTPException(400, "Invalid top-up")
        x["wallet"] += n; await save()
    return {"wallet": x["wallet"]}


@app.get("/")
def index(): return FileResponse("static/index.html")
app.mount("/static", StaticFiles(directory="static"), name="static")
