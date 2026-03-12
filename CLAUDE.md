# CLAUDE.md — pentester.lt Project Bible
## What We Are Building
**pentester.lt** — An external attack surface scanning platform for Lithuanian organizations that must comply with the Kibernetinio saugumo įstatymas (KSĮ / Lithuanian Cybersecurity Law, implementing NIS2/TIS2).
The product scans what is publicly visible about an organization from the outside — no internal network access required. Every month, clients receive a Lithuanian-language PDF report showing what is broken, how serious it is, and what to fix first.
**Target customer:** CISOs, IT managers, and directors of Lithuanian organizations registered in the NKSC Kibernetinio saugumo subjektų registras (up to 2,000 organizations legally obligated to comply).
**Core value proposition:** The law requires vulnerability scanning every 6 months. We do it every month and produce the evidence document automatically.
---
## Tech Stack
- **Frontend:** Next.js 14 (App Router)
- **Database:** Supabase (PostgreSQL with Row Level Security)
- **Auth:** Supabase Auth with MFA enforced
- **Storage:** Supabase Storage (encrypted PDF reports)
- **Scan orchestration:** Python (server-side API calls to third party services)
- **PDF generation:** Server-side only (Puppeteer or WeasyPrint)
- **Deployment:** Vercel (frontend) + separate secure backend for scan engine
- **AI:** Claude API (claude-sonnet-4-20250514) for Lithuanian finding descriptions
- **Language:** TypeScript throughout
---
## Database Schema
```sql
-- Organizations (clients)
organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  domain text NOT NULL UNIQUE,
  verified boolean DEFAULT false, -- domain ownership verified
  verification_token text,
  contact_email text NOT NULL,
  sector text, -- KSĮ sector classification
  created_at timestamptz DEFAULT now()
)
-- Users
profiles (
  id uuid PRIMARY KEY REFERENCES auth.users,
  org_id uuid REFERENCES organizations,
  role text CHECK (role IN ('admin', 'viewer')),
  created_at timestamptz DEFAULT now()
)
-- Scans
scans (
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES organizations,
  scan_type text CHECK (scan_type IN ('light', 'deep')),
  status text CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  triggered_by uuid REFERENCES profiles,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz DEFAULT now()
)
-- Findings
findings (
  id uuid PRIMARY KEY,
  scan_id uuid REFERENCES scans,
  org_id uuid REFERENCES organizations,
  module text NOT NULL, -- shodan, hibp, ssl, mxtoolbox, securitytrails, virustotal, abuseipdb, urlscan
  severity text CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title_lt text NOT NULL, -- Lithuanian title
  description_lt text NOT NULL, -- Lithuanian description
  recommendation_lt text NOT NULL, -- Lithuanian remediation advice
  nis2_article text, -- which KSĮ/NIS2 article this relates to
  evidence jsonb, -- raw API response data
  created_at timestamptz DEFAULT now()
)
-- Reports
reports (
  id uuid PRIMARY KEY,
  scan_id uuid REFERENCES scans,
  org_id uuid REFERENCES organizations,
  pdf_path text, -- Supabase Storage path
  risk_score integer CHECK (risk_score BETWEEN 0 AND 100),
  critical_count integer DEFAULT 0,
  high_count integer DEFAULT 0,
  medium_count integer DEFAULT 0,
  low_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now()
)
-- Audit log
audit_log (
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES organizations,
  user_id uuid REFERENCES profiles,
  action text NOT NULL,
  details jsonb,
  ip_address text,
  created_at timestamptz DEFAULT now()
)
```
---
## Security Requirements — NON-NEGOTIABLE
These apply to every single feature. Never bypass them.
### 1. Row Level Security (RLS)
- **Every table has RLS enabled**
- Users can ONLY access data belonging to their own organization
- No exceptions. Enforce at database level, not just application level.
```sql
-- Example RLS policy pattern for every table
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "org_isolation" ON findings
USING (org_id = (SELECT org_id FROM profiles WHERE id = auth.uid()));
```
### 2. Domain Ownership Verification
- Before ANY scan runs, the domain must be verified as owned by the client
- Verification method: DNS TXT record containing a unique token
- A scan job MUST check `organizations.verified = true` before proceeding
- Never scan a domain that is not verified
### 3. API Keys
- All third party API keys (Shodan, HIBP, SecurityTrails, VirusTotal, AbuseIPDB, URLScan, MXToolbox, SSL Labs) live in server-side environment variables ONLY
- Never exposed to frontend
- Never logged
- Never included in any client-side code or response
### 4. PDF Reports
- Generated server-side only — never in browser
- Stored in Supabase Storage with private bucket
- Accessed via signed URLs with 1-hour expiry only
- Never publicly accessible by URL
### 5. Authentication
- Supabase Auth only
- MFA enforced for all accounts
- Session tokens validated server-side on every protected route
- No magic links in production
### 6. Audit Logging
- Every scan trigger logged (who, when, from which IP)
- Every report download logged
- Every login attempt logged
- Logs are immutable — no delete or update operations on audit_log
### 7. Input Validation
- All domain inputs sanitized and validated (regex: valid domain format only)
- All IP range inputs validated (CIDR format only)
- No user input ever passed directly to API calls without sanitization
- Rate limit all API endpoints (max 10 requests/minute per user)
### 8. Scan Job Security
- Scan jobs run in isolated server environment
- Scan results stored only after job completes successfully
- Failed scans log error but never expose raw API error messages to frontend
- Scan queue prevents duplicate concurrent scans for same organization
---
## Scan Modules — MVP v1.0
Eight modules. All run server-side. Results stored as findings in database.
| Module | API | What it checks | Severity logic |
|--------|-----|----------------|----------------|
| `shodan` | Shodan API | Open ports, exposed services, CVEs on detected software | Critical if known CVE, High if sensitive service exposed |
| `hibp` | HaveIBeenPwned | Breached emails by domain, password exposure | Critical if passwords exposed, High if emails in breach |
| `ssl` | SSL Labs API | Certificate validity, expiry, cipher strength | Critical if expired, High if expiring <30 days or weak cipher |
| `mxtoolbox` | MXToolbox API | SPF, DKIM, DMARC configuration | High if missing DMARC, Medium if misconfigured |
| `securitytrails` | SecurityTrails API | Subdomains, DNS history, dangling records | High if dangling subdomain, Medium if suspicious history |
| `virustotal` | VirusTotal API | Domain/IP reputation, malware associations | Critical if flagged by 3+ vendors |
| `abuseipdb` | AbuseIPDB API | IP abuse reports | High if abuse confidence >50% |
| `urlscan` | URLScan.io API | Lookalike domains, phishing detection | Critical if active phishing detected |
---
## Lithuanian Report Structure
Report generated as PDF, fully in Lithuanian language.
### Page 1 — Executive Summary
- Organization name and scan date
- **Rizikos balas** (Risk score) — 0-100, displayed as RAG (Red/Amber/Green)
- **Kritinių problemų skaičius** — count of critical findings
- **Palyginimas su praėjusiu skaitymu** — delta vs previous scan
- **3 svarbiausios problemos** — top 3 priority actions in plain language
- **KSĮ atitikties statusas** — which law articles are at risk
### Pages 2+ — Findings Detail
For each finding:
- Pavadinimas (title in Lithuanian)
- Sunkumo lygis (severity: Kritinis / Aukštas / Vidutinis / Žemas)
- Aprašymas (plain Lithuanian explanation, no jargon)
- Įrodymai (evidence — domain, IP, specific data found)
- KSĮ straipsnis (which article of the law this violates)
- Rekomenduojami veiksmai (remediation steps)
### Appendix
- Raw technical data for IT team
- Scan scope (domains checked)
- Scan timestamp and module list
- Data sources used
---
## KSĮ Article Mapping
Map findings to these specific law requirements:
| Finding type | KSĮ Article | Requirement |
|---|---|---|
| Open ports / exposed services | Art. 11(2)(e) | Tinklų saugumas |
| Breached credentials | Art. 11(2)(i) | Prieigos valdymas ir MFA |
| Missing DMARC/SPF | Art. 11(2)(i) | Tapatumo nustatymo priemonės |
| Expired/weak certificates | Art. 11(2)(e) | Tinklų saugumas |
| Dangling subdomains | Art. 11(2)(a) | Rizikų valdymas |
| Dark web exposure | Art. 11(2)(b) | Incidentų valdymas |
| Phishing domains | Art. 11(2)(b) | Incidentų valdymas |
| Malware/reputation flags | Art. 11(2)(e) | Tinklų saugumas |
---
## Claude API Usage
Use Claude API for:
1. Generating natural Lithuanian descriptions of findings from raw API data
2. Generating plain-language remediation recommendations in Lithuanian
3. Generating the executive summary paragraph on page 1
**System prompt for finding generation:**
```
Tu esi kibernetinio saugumo ekspertas, rašantis ataskaitas lietuviškoms organizacijoms.
Rašyk aiškiai ir suprantamai — taip, kad IT vadovas, kuris nėra techninis specialistas, suprastų problemą ir žinotų, ką daryti.
Nenaudok žargono be paaiškinimo. Būk konkretus ir glaustas.
```
**Model:** claude-sonnet-4-20250514
**Max tokens:** 500 per finding description
**Temperature:** 0.3 (consistent, professional output)
---
## Environment Variables Required
```
# Supabase
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
# Third party scan APIs (server-side only, never expose to client)
SHODAN_API_KEY=
HIBP_API_KEY=
SECURITYTRAILS_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
URLSCAN_API_KEY=
MXTOOLBOX_API_KEY=
# Claude API
ANTHROPIC_API_KEY=
# App
NEXTAUTH_SECRET=
NEXT_PUBLIC_APP_URL=https://pentester.lt
```
---
## Project Structure
```
pentester-lt/
├── app/                        # Next.js App Router
│   ├── (auth)/
│   │   ├── login/
│   │   └── register/
│   ├── (dashboard)/
│   │   ├── dashboard/          # Main client view
│   │   ├── scans/              # Scan history
│   │   ├── reports/            # Report download
│   │   └── settings/           # Domain management, verification
│   └── api/
│       ├── scan/               # Trigger scan endpoint
│       ├── reports/            # Report generation endpoint
│       └── verify-domain/      # Domain verification endpoint
├── lib/
│   ├── supabase/               # Supabase client
│   ├── scanners/               # One file per module
│   │   ├── shodan.ts
│   │   ├── hibp.ts
│   │   ├── ssl.ts
│   │   ├── mxtoolbox.ts
│   │   ├── securitytrails.ts
│   │   ├── virustotal.ts
│   │   ├── abuseipdb.ts
│   │   └── urlscan.ts
│   ├── report/                 # PDF generation
│   │   ├── generator.ts
│   │   └── templates/
│   └── claude/                 # Claude API for Lithuanian text
├── components/
├── types/
└── CLAUDE.md                   # This file
```
---
## Build Order — Session by Session
### Session 1 — Foundation
- Supabase project setup with full schema and RLS policies
- Next.js project scaffold
- Auth flow (login, register, MFA)
- Domain verification flow (DNS TXT token)
### Session 2 — First Scanner
- Shodan module working end to end
- Domain input → API call → findings stored in database
- Basic dashboard showing raw findings
### Session 3 — Remaining Scanners
- HIBP, SSL Labs, MXToolbox modules
- SecurityTrails, VirusTotal, AbuseIPDB, URLScan modules
- Scan orchestration (run all 8 in parallel, aggregate results)
### Session 4 — Report Generation
- Risk scoring algorithm
- Claude API integration for Lithuanian text
- PDF report generation (page 1 + findings pages)
- Supabase Storage upload + signed URL delivery
### Session 5 — Dashboard & Polish
- Scan history view
- Report download with audit logging
- Risk score trend chart
- Manual scan trigger with status polling
### Session 6 — Security Hardening
- Rate limiting on all endpoints
- Full RLS audit
- Input validation review
- Penetration test your own platform using your own tool
---
## Lithuanian Language Requirements — NON-NEGOTIABLE
### Language Standard
- **All user-facing text is in Lithuanian** — every label, button, error message, report, email notification
- Language must be **professional, formal, and legally precise** — this platform is used by CISOs and IT directors, not consumers
- **No machine-translated feel** — all Lithuanian text must be reviewed for natural professional register
- Use **official Lithuanian cybersecurity terminology** as established in NKSC publications and legal acts
- No anglicisms unless the term has no established Lithuanian equivalent (e.g. "phishing" → "sukčiavimas apsimetant", "firewall" → "užkarda", "malware" → "kenkėjiška programinė įranga")
### Official Terminology Reference
| English | Official Lithuanian term | Source |
|---|---|---|
| Cybersecurity | Kibernetinis saugumas | KSĮ |
| Vulnerability | Pažeidžiamumas | KSĮ |
| Vulnerability scanning | Pažeidžiamumų skenavimas | KSRA |
| Incident | Kibernetinis incidentas | KSĮ |
| Risk management | Rizikos valdymas | KSĮ |
| Attack surface | Atakos paviršius | NKSC |
| Essential entity | Esminis subjektas | KSĮ |
| Important entity | Svarbus subjektas | KSĮ |
| Network security | Tinklų ir informacinių sistemų saugumas | KSĮ |
| Access control | Prieigos kontrolė | KSĮ |
| Multi-factor authentication | Kelių veiksnių autentifikavimas | KSĮ |
| Supply chain | Tiekimo grandinė | KSĮ |
| NKSC | Nacionalinis kibernetinio saugumo centras | — |
| Audit | Auditas / patikrinimas | — |
| Finding | Nustatytas trūkumas / pažeidimas | — |
| Remediation | Pažeidimo šalinimas | — |
| Report | Ataskaita | — |
| Risk score | Rizikos balas | — |
| Compliance | Atitiktis | — |
---
## Legal Grounding — Teisinis Pagrindas
Every report and UI element referencing compliance **must cite specific legal acts and articles**, not generic "NIS2 compliance."
### Primary Legal Acts
**1. Kibernetinio saugumo įstatymas (KSĮ)**
- Priimtas: 2024-10-03, įsigaliojo: 2024-10-18
- Perkelia: NIS2 direktyvą (ES 2022/2555) ir TIS2 direktyvą
- NKSC registras: iki 2,000 organizacijų
- Atsakomybė: asmeninė vadovo atsakomybė (iki 10 mln. EUR arba 2% metinės apyvartos)
**2. Kibernetinio saugumo reikalavimų aprašas (KSRA)**
- Subįstatyminis teisės aktas, detalizuojantis KSĮ techninius reikalavimus
- **KSRA 45.8 straipsnis** — pažeidžiamumų skenavimas privalomas ne rečiau kaip kas 6 mėnesiai
- Mūsų platforma: mėnesinis skenavimas → automatiškai viršija įstatymo reikalavimą
**3. ES NIS2 direktyva (2022/2555)**
- Perkelta į LT teisę per KSĮ
- Sektoriai: energetika, transportas, sveikatos apsauga, skaitmeninė infrastruktūra, IT paslaugos, viešasis administravimas, vandentiekis, bankininkystė, maisto pramonė, gamyba, moksliniai tyrimai, pašto paslaugos, atliekų tvarkymas
### KSĮ Article Citations in Reports
Every finding in the PDF report must cite the specific KSĮ article:
| Pažeidimo tipas | KSĮ straipsnis | Citata |
|---|---|---|
| Atidaryti prievadai / eksponuotos paslaugos | 11 str. 2 d. 5 p. | „tinklų ir informacinių sistemų saugumo priemonės" |
| Nutekėję slaptažodžiai / pažeisti prisijungimai | 11 str. 2 d. 9 p. | „prieigos kontrolės ir tapatybės valdymo priemonės, įskaitant kelių veiksnių autentifikavimą" |
| Trūkstamas DMARC/SPF | 11 str. 2 d. 9 p. | „prieigos kontrolės ir tapatybės valdymo priemonės" |
| Pasibaigęs / silpnas sertifikatas | 11 str. 2 d. 5 p. | „tinklų ir informacinių sistemų saugumo priemonės" |
| Kabantis subdomeinas | 11 str. 2 d. 1 p. | „rizikos valdymo politikos" |
| Reputacijos problemos | 11 str. 2 d. 2 p. | „incidentų valdymo procedūros" |
| Sukčiavimo domenai | 11 str. 2 d. 2 p. | „incidentų valdymo procedūros" |
### Legal Language in Reports
Each report must contain this footer on every page:
> *Ši ataskaita parengta vadovaujantis Kibernetinio saugumo įstatymo (2024 m. spalio 3 d. Nr. XIV-2960) ir Kibernetinio saugumo reikalavimų aprašo reikalavimais. Nustatyti trūkumai vertinami pagal NKSC paskelbtas gaires ir ES NIS2 direktyvos (2022/2555) nuostatas.*
Each report executive summary must contain:
> *Pagal Kibernetinio saugumo reikalavimų aprašo 45.8 punktą, organizacijos privalo atlikti pažeidžiamumų skenavimą ne rečiau kaip kartą per 6 mėnesius. Ši ataskaita įrodo, kad reikalavimas įvykdytas [DATA].*
### NKSC Audit Evidence Block
Every report appendix must contain a structured block explicitly designed for NKSC audit purposes:
```
NKSC PATIKRINIMO ĮRODYMAS
───────────────────────────────────────────────
Organizacija:        [pavadinimas]
Domenas:             [domenas]
Skenavimo data:      [data ir laikas UTC+2]
Skenavimo metodas:   Automatinis išorinis pažeidžiamumų skenavimas
Apimtis:             Viešai prieinami ištekliai (domenas ir IP adresai)
Teisinis pagrindas:  KSRA 45.8 str.
Platformos operatorius: [UAB pavadinimas], [el. paštas]
Ataskaitos ID:       [unikalus ID]
───────────────────────────────────────────────
Šis dokumentas gali būti pateiktas NKSC kaip pažeidžiamumų
skenavimo įvykdymo įrodymas pagal KSĮ reikalavimus.
```
---
## What NOT to Build in MVP
- Scheduled automatic scans — manual trigger only
- IP range scanning — domain only
- Supplier scan module
- Multi-client consultant view
- KSIS integration or compliance document generation
- Payment/billing (invoice manually for first clients)
- Dark web / Intelligence X (add in v1.1 when API approved)
---
## Definition of Done for MVP
- [ ] Client can register and verify their domain
- [ ] Client can trigger a manual scan
- [ ] All 8 scan modules run and store findings
- [ ] Lithuanian PDF report generated and downloadable
- [ ] Risk score displayed on dashboard
- [ ] Scan history visible
- [ ] All data isolated by organization (RLS verified)
- [ ] Klaipėda University live as client zero
- [ ] Platform passes its own scan with no critical findings
