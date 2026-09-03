# Backend - MCP Security Framework

Backend FastAPI du **MCP Security Framework**.

Le backend constitue le plan de contrôle applicatif du framework. Il centralise
l'inventaire MCP, l'analyse des tools, les identités et autorisations, la
configuration de sécurité publiée, les décisions Runtime, les traces, l'audit et
les opérations d'administration.

## État actuel

Le cœur Runtime Security est implémenté et validé. Le backend couvre notamment :

- inventaire des serveurs et tools MCP ;
- découverte/import MCP gouverné ;
- Tool Description Analyzer avec fingerprint, drift et workflow de revue ;
- Control Plane avec rôles `ADMIN` et `VIEWER` ;
- révisions de configuration `DRAFT -> VALIDATE -> PUBLISH -> ROLLBACK` ;
- Security Contracts, Security Packs et Trusted Adapter SDK ;
- identités agent, trusted sessions, capabilities et authority-qualified scopes ;
- construction du contexte Runtime et décision via OPA/Rego ;
- Emergency Deny ;
- Runtime Calls, Audit et Operations ;
- Controlled AI Assistance, strictement advisory-only ;
- support d'authentification upstream NONE, Bearer et OAuth ;
- Result Guard ;
- Build Security avec intake Local/Git/Inventory, Semgrep, Gitleaks et Trivy ;
- assessment déterministe `PASS / WARN / BLOCK / ERROR`, historique des findings et audit ;
- publication optionnelle de preuves Build dans une révision Control Plane signée,
  puis gate Runtime autoritatif dans OPA.

Le module Deploy Security (AWS/IAM) constitue la phase suivante.

## Installation locale

La procédure supportée part de la racine du dépôt et utilise le bootstrap
principal :

```powershell
python scripts/check_dependencies.py
python scripts/setup_local_environment.py
```

Le bootstrap crée `backend/.venv`, installe le fichier unique
`backend/requirements.txt`, provisionne OPA, les modèles locaux, Semgrep,
Gitleaks, Trivy et la base de vulnérabilités Trivy, génère les identités internes,
prépare PostgreSQL, initialise le schéma et crée la configuration publiée initiale.
Les binaires Build sont gérés sous `.runtime/tools` et ne nécessitent pas
d'installation système manuelle.

Pour le chemin local par défaut, aucune création manuelle du user ou de la base
PostgreSQL n'est requise : le setup peut initialiser un cluster propre au projet
sous `.runtime/postgres`.

## Lancement

Depuis la racine du dépôt :

```powershell
.\backend\.venv\Scripts\python.exe scripts\start_framework.py
```

Le superviseur démarre ou réutilise PostgreSQL, OPA, le fournisseur d'identité
local, le backend FastAPI et la Gateway MCP.

Le frontend est lancé séparément :

```powershell
cd frontend
npm.cmd run dev
```

Backend par défaut :

```text
http://127.0.0.1:8000
```

Swagger :

```text
http://127.0.0.1:8000/docs
```

## PostgreSQL

La configuration locale par défaut provient de `.env.example` :

```env
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=55432
POSTGRES_DB=mcp_security
POSTGRES_USER=mcp_user
POSTGRES_PASSWORD=<generate-local>
```

Le mot de passe local est généré dans le fichier ignoré `.env` lors du premier
setup et n'est jamais affiché. Pour un PostgreSQL externe, l'opérateur renseigne
explicitement les paramètres `POSTGRES_*`.

PostgreSQL reste la source de vérité administrative du Runtime. Les fichiers
YAML suivis dans Git servent uniquement au bootstrap/import, aux exemples et aux
tests ; ils ne constituent pas un fallback silencieux de la configuration
Runtime publiée.

## Policy Engine

OPA/Rego est le moteur de politique Runtime autoritatif.

Le flux principal est :

```text
Gateway
  -> identité / session / autorisations
  -> Tool Analyzer / Security Contract
  -> ressources canoniques / scopes
  -> contexte signé
  -> OPA/Rego
  -> ALLOW ou BLOCK
  -> exécution MCP uniquement si autorisée
```

Le framework applique une logique fail-closed : une identité invalide, un
contexte incomplet, une configuration publiée invalide, une ressource non
résolue ou une décision OPA indisponible ne devient jamais une autorisation
implicite.

## Tests

Toutes les dépendances Python nécessaires au Runtime et aux validations,
y compris `pytest`, sont épinglées dans le même fichier :

```powershell
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python.exe -m pytest -q
```

Les politiques OPA disposent également de leurs propres tests sous
`policies/opa/`.

## Sécurité des secrets

Ne jamais committer :

- `.env` ;
- `.runtime` ;
- les clés privées ;
- les tokens OAuth/Bearer ;
- les caches ou modèles locaux.

Chaque installation génère son propre matériel cryptographique. Un clone ne doit
jamais réutiliser le dossier `.runtime` d'une autre machine.
