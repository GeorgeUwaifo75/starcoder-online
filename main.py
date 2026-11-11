import os, re, copy, time, uuid, hashlib, secrets, asyncio
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
SYS = {"max_tx": 50000, "copies": 1, "footer": "Thanks for purchasing from us today. Please come back.", "lang": "en", "currency": "NGN"}
CURRENCIES = ("NGN", "PESO", "USD", "EUR", "GBP", "KES", "GHS")
KEYS = {"users": {}, "company": {}, "system": {}, "products": {}, "sales": [], "purchases": [], "misc": [], "deleted": [], "deleted_products": []}

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
        DB["company"][uid] = {"name": co, "address": "", "phone": "", "email": "", "logo": "", "show_logo": True, "vat": 0}
        es = b.get("lang") == "es"   # Spanish defaults: pesos + Spanish receipt footer
        DB["system"][uid] = dict(SYS, **({"lang": "es", "currency": "PESO", "footer": "Gracias por su compra. Vuelva pronto."} if es else {}))
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


@app.delete("/api/products/{code}")
async def delete_product(code: str, u=Depends(admin)):
    t, key = u["tenant"], f"{u['tenant']}:{code}"
    async with lock:
        p = DB["products"].pop(key, None)
        if not p: raise HTTPException(404, "Not found")
        DB["deleted_products"].append({"id": uuid.uuid4().hex[:8], "tenant": t, "ts": now(), "by": u["id"], "by_name": u["name"], "product": p})
        try: await save()
        except Exception:
            DB["products"][key] = p; DB["deleted_products"].pop(); raise   # failed save: put everything back
    return {"deleted": code}


@app.get("/api/deleted-products")
def deleted_products(u=Depends(admin)): return [x for x in DB["deleted_products"] if x["tenant"] == u["tenant"]]


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
        DB["company"][t] = {k: str(c.get(k, "")) for k in ("name", "address", "phone", "email", "logo")} | {"vat": max(0, num(c.get("vat"))), "show_logo": bool(c.get("show_logo", True))}
        DB["system"][t] = {"max_tx": int(num(s.get("max_tx"), 50000)), "copies": max(1, int(num(s.get("copies"), 1))),
                           "footer": str(s.get("footer", SYS["footer"])),
                           "lang": s.get("lang") if s.get("lang") in ("en", "es") else DB["system"].get(t, SYS)["lang"],
                           "currency": s.get("currency") if s.get("currency") in CURRENCIES else DB["system"].get(t, SYS)["currency"]}
        await save()
    return info(u)


@app.get("/api/backup")
def backup(u=Depends(admin)):
    t = u["tenant"]
    d = {k: [x for x in DB[k] if x["tenant"] == t] for k in ("sales", "purchases", "misc", "deleted", "deleted_products")}
    d["products"] = [p for p in DB["products"].values() if p["tenant"] == t]
    d["company"], d["system"] = DB["company"].get(t), DB["system"].get(t)
    return d


@app.post("/api/restore")
async def restore(b: dict, u=Depends(admin)):
    t = u["tenant"]
    async with lock:
        for k in ("sales", "purchases", "misc", "deleted", "deleted_products"):
            DB[k] = [x for x in DB[k] if x["tenant"] != t] + [dict(x, tenant=t) for x in b.get(k, [])]
        DB["products"] = {k: v for k, v in DB["products"].items() if v["tenant"] != t}
        for p in b.get("products", []): p["tenant"] = t; DB["products"][f"{t}:{p['code']}"] = p
        if b.get("company"): DB["company"][t] = b["company"]
        if b.get("system"): DB["system"][t] = b["system"]
        await save()
    return {"ok": True}



# ---------- administrator import tool (Excel / JSON rows sent by the browser) ----------
IMPORT_MAX = 2000
ALIASES = {   # accepted column names, normalised: lower-case letters and digits only
    "company": {"name": ["name", "companyname", "company", "businessname"], "address": ["address"], "phone": ["phone", "telephone", "tel"],
                "email": ["email", "emailaddress"], "vat": ["vat", "vatpercent", "tax"], "logo": ["logo", "logourl"], "show_logo": ["showlogo", "uselogo"]},
    "system": {"max_tx": ["maxtx", "maxtransactions", "maximumnumberoftransactions"], "copies": ["copies", "receiptcopies"],
               "footer": ["footer", "receiptfooter"], "lang": ["lang", "language"], "currency": ["currency"]},
    "users": {"id": ["id", "userid"], "first": ["first", "firstname"], "last": ["last", "lastname"], "password": ["password"], "role": ["role"],
              "reports": ["reports", "viewreports"], "users": ["users", "createusers"], "delete_last": ["deletelast", "deletelasttransaction"],
              "active": ["active", "status"]},
    "products": {"code": ["code", "productcode", "barcode", "sku"], "name": ["name", "productname"], "desc": ["desc", "description", "productdescription"],
                 "cost": ["cost", "costprice", "unitcost"], "ptype": ["ptype", "type", "producttype"], "price": ["price", "salesprice", "sellingprice"],
                 "w1": ["w1", "wholesale1", "wholesaleprice1"], "w2": ["w2", "wholesale2", "wholesaleprice2"], "discount": ["discount", "discountpercent"],
                 "qty": ["qty", "quantity", "initialquantity", "stock"], "supplier": ["supplier", "suppliername"], "phone": ["phone", "supplierphone"],
                 "min": ["min", "minstock", "minimumstock"], "max": ["max", "maxstock", "maximumstock"], "image": ["image", "imageurl", "photo"]}}
ROLES = {"admin": "admin", "administrator": "admin", "semi": "semi", "semiadmin": "semi", "semiadministrator": "semi", "user": "user", "normal": "user", "normaluser": "user"}


def nk(s): return re.sub(r"[^a-z0-9]", "", str(s).lower())
def pick(nr, typ, f):
    for a in ALIASES[typ][f]:
        v = nr.get(a)
        if v is not None and str(v).strip() != "": return v
    return None
def txt(x, n=200):
    if x is None: return ""
    if isinstance(x, float) and x.is_integer(): x = int(x)
    return str(x).strip()[:n]
def flt(x, label, lo=0, hi=None):
    if isinstance(x, (int, float)) and not isinstance(x, bool): v = float(x)
    else:
        try: v = float(re.sub(r"[^\d.\-]", "", str(x)))
        except ValueError: raise ValueError(f"{label}: must be a number")
    if v != v or v < lo or (hi is not None and v > hi):
        raise ValueError(f"{label}: must be between {lo:g} and {hi:g}" if hi is not None else f"{label}: must be {lo:g} or more")
    return v
def tf(x, label="Yes/No"):
    if x is None: return None
    s = str(x).strip().lower()
    if s in ("1", "true", "yes", "y", "x", "active", "on"): return True
    if s in ("0", "false", "no", "n", "off", "disabled", "inactive"): return False
    raise ValueError(f"{label}: Yes/No value expected")


def imp_product(u, t, nr, mode, seen, dry):
    P = lambda f: pick(nr, "products", f)
    D = lambda f, d: d if P(f) is None else P(f)
    code, name = txt(P("code"), 60), txt(P("name"), 120)
    if not code or not name: return "error", "Product code and name are required", code or name or "-"
    if code in seen: return "error", "Duplicate code in file", code
    seen.add(code)
    try:
        cost, price, w1, w2 = (flt(D(f, 0), l) for f, l in (("cost", "Cost"), ("price", "Price"), ("w1", "Wholesale price #1"), ("w2", "Wholesale price #2")))
        disc = flt(D("discount", 0), "Discount", 0, 100)
        mn, mx = flt(D("min", 5), "Min stock"), flt(D("max", 20), "Max stock")
        if mx < mn: raise ValueError("Max stock: must be at least Min stock")
        pt = nk(D("ptype", "discrete"))
        if pt in ("discrete", "whole", "unit", "units", "integer"): pt = "discrete"
        elif pt in ("float", "fractional", "fraction", "decimal", "weight", "volume"): pt = "float"
        else: raise ValueError("Type: must be discrete or fractional")
        qty = flt(D("qty", 0), "Initial quantity")
        if pt == "discrete" and qty != int(qty): raise ValueError("Initial quantity: must be a whole number")
        img = txt(P("image"), 500)
        if img and not img.startswith("https://"): raise ValueError("Image: must be an https link")
    except ValueError as e: return "error", str(e), code
    key = f"{t}:{code}"; old = DB["products"].get(key)
    if old and mode != "update": return "skip", "Already exists", code
    f = {"code": code, "name": name, "cost": cost, "ptype": pt, "price": price, "w1": w1, "w2": w2, "discount": disc,
         "supplier": txt(P("supplier"), 120), "phone": txt(P("phone"), 40), "min": mn, "max": mx, "tenant": t}
    if not dry:
        if old:
            DB["products"][key] = {**old, **f, "desc": txt(P("desc"), 300) or old.get("desc") or name, "image": img or old.get("image", "")}
        else:
            p = DB["products"][key] = {**f, "desc": txt(P("desc"), 300) or name, "image": img, "qty": 0}
            if qty > 0: add_purchase(u, p, qty, cost, f["supplier"])   # opening stock is recorded as a purchase
    return ("update" if old else "add"), "", code


def imp_user(u, t, nr, mode, seen, dry):
    P = lambda f: pick(nr, "users", f)
    uid = txt(P("id"), 80).lower(); first, last, pw = txt(P("first"), 60), txt(P("last"), 60), txt(P("password"), 100)
    try:
        role = None
        if P("role") is not None:
            role = ROLES.get(nk(P("role")))
            if not role: raise ValueError("Role: must be administrator, semi or user")
        flags = {k: tf(P(k), l) for k, l in (("reports", "Reports"), ("users", "Create users"), ("delete_last", "Delete last transaction"))}
        active = tf(P("active"), "Active")
        if pw and len(pw) < 6: raise ValueError("Password: must be at least 6 characters")
        if bool(first) != bool(last): raise ValueError("First and last name are required")
    except ValueError as e: return "error", str(e), uid or f"{first} {last}".strip() or "-"
    if uid:
        if uid in seen: return "error", "Duplicate User ID in file", uid
        seen.add(uid)
        x = DB["users"].get(uid)
        if not x or x["tenant"] != t: return "error", "User ID not found (leave blank to create a new user)", uid
        if mode != "update": return "skip", "Already exists", uid
        if uid in (u["id"], t) and ((role and role != x["role"]) or active is False):
            return "error", "You cannot change your own role, or deactivate yourself", uid
        if not dry:
            if first: x["name"] = f"{first} {last}"
            if role: x["role"] = role
            if active is not None: x["active"] = active
            x["perms"] = {**x["perms"], **{k: v for k, v in flags.items() if v is not None}}
            if pw:
                x["pw"] = hp(pw)
                for tok in [k for k, v in SESS.items() if v == uid and uid != u["id"]]: del SESS[tok]
        return "update", "", uid
    if not (first and last and pw): return "error", "First and last name and a password are required", f"{first} {last}".strip() or "-"
    if not dry:
        new = new_user(first, last, pw, role or "user", t, {k: bool(v) for k, v in flags.items()})
        if active is False: DB["users"][new]["active"] = False
        return "add", "", new
    return "add", "", f"{first}.{last}".lower().replace(" ", "")


def imp_company(u, t, nr, mode, seen, dry):
    G = lambda f: pick(nr, "company", f)
    try:
        vat = flt(G("vat"), "VAT", 0, 100) if G("vat") is not None else None
        email, logo = txt(G("email"), 120), txt(G("logo"), 500)
        if email and "@" not in email: raise ValueError("Email: not valid")
        if logo and not logo.startswith("https://"): raise ValueError("Logo: must be an https link")
        sl = tf(G("show_logo"), "Show logo")
    except ValueError as e: return "error", str(e), "-"
    cur = DB["company"].get(t, {}); new = dict(cur)
    for f, v in (("name", txt(G("name"), 120)), ("address", txt(G("address"), 200)), ("phone", txt(G("phone"), 40)), ("email", email), ("logo", logo)):
        if v: new[f] = v
    if vat is not None: new["vat"] = vat
    if sl is not None: new["show_logo"] = sl
    if new == cur: return "skip", "Nothing to import", cur.get("name", "-")
    if not dry: DB["company"][t] = new
    return "update", "", new.get("name", "-")


def imp_system(u, t, nr, mode, seen, dry):
    G = lambda f: pick(nr, "system", f)
    try:
        mt = int(flt(G("max_tx"), "Max transactions", 1)) if G("max_tx") is not None else None
        cp = int(flt(G("copies"), "Receipt copies", 1, 10)) if G("copies") is not None else None
        lang = nk(G("lang")) if G("lang") is not None else None
        if lang in ("english", "inglés", "ingles"): lang = "en"
        if lang in ("spanish", "español", "espanol"): lang = "es"
        if lang is not None and lang not in ("en", "es"): raise ValueError("Language: must be en or es")
        cur_ = txt(G("currency"), 10).upper() if G("currency") is not None else None
        if cur_ is not None and cur_ not in CURRENCIES: raise ValueError("Currency: not supported")
    except ValueError as e: return "error", str(e), "-"
    cur = DB["system"].get(t, SYS); new = dict(cur)
    for k, v in (("max_tx", mt), ("copies", cp), ("footer", txt(G("footer"), 200) or None), ("lang", lang), ("currency", cur_)):
        if v is not None: new[k] = v
    if new == cur: return "skip", "Nothing to import", "-"
    if not dry: DB["system"][t] = new
    return "update", "", new.get("currency", "-")


HANDLERS = {"products": imp_product, "users": imp_user, "company": imp_company, "system": imp_system}


@app.post("/api/import")
async def import_data(b: dict, u=Depends(admin)):
    typ = b.get("type")
    if typ not in HANDLERS: raise HTTPException(400, "Unknown import type")
    rows = b.get("rows"); rows = [rows] if isinstance(rows, dict) else rows
    if not isinstance(rows, list) or not rows: raise HTTPException(400, "No rows found in the file")
    if len(rows) > IMPORT_MAX: raise HTTPException(400, f"Too many rows (maximum {IMPORT_MAX} per import)")
    mode, dry, t = ("update" if b.get("mode") == "update" else "add"), bool(b.get("dry_run")), u["tenant"]
    if typ in ("company", "system"): rows = rows[:1]   # these are single records
    out, summ = [], {"add": 0, "update": 0, "skip": 0, "error": 0}
    async with lock:
        snap = None if dry else copy.deepcopy({k: DB[k] for k in ("users", "company", "system", "products", "purchases")})
        seen = set()
        for i, r in enumerate(rows, 1):
            st, msg, lab = ("error", "Row is not valid", "-") if not isinstance(r, dict) else HANDLERS[typ](u, t, {nk(k): v for k, v in r.items()}, mode, seen, dry)
            summ[st] += 1; out.append({"row": i, "status": st, "msg": msg, "label": lab})
        if not dry and (summ["add"] or summ["update"]):
            try: await save()
            except Exception:
                DB.update(snap); raise   # a failed save never leaves a half-applied import in memory
    return {"dry_run": dry, "summary": summ, "rows": out[:500], "total": len(out)}


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


@app.get("/favicon.ico", include_in_schema=False)
def favicon(): return FileResponse("static/favicon.ico")
app.mount("/static", StaticFiles(directory="static"), name="static")
