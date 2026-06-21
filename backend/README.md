# Backend - MCP Security Framework

Backend FastAPI minimal du projet MCP Security Framework.

## Objectif

Ce backend servira à centraliser progressivement :

- l’inventaire MCP ;
- les outils MCP ;
- les politiques de sécurité ;
- les décisions runtime ;
- les journaux d’exécution ;
- les événements d’audit ;
- les futurs résultats de scans ;
- les rapports.

## Lancement local

Depuis le dossier `backend/` :

```bash
python -m venv .venv
```

Windows :

```bash
.venv\Scripts\activate
```

Linux/macOS :

```bash
source .venv/bin/activate
```

Installer les dépendances :

```bash
pip install -r requirements.txt
```

Lancer le backend :

```bash
uvicorn app.main:app --reload
```

## Routes disponibles

```text
GET /
GET /api/v1/health
GET /api/v1/status
GET /api/v1/db-check
GET /api/v1/servers
POST /api/v1/servers
GET /api/v1/tools
POST /api/v1/tools
GET /api/v1/policies
POST /api/v1/policies
GET /api/v1/runtime/logs
POST /api/v1/runtime/logs
```

## Initialisation de la base de données

Depuis le dossier `backend/` :

```bash
python -m app.db.init_db
```

Tables créées :

- mcp_servers
- mcp_tools
- policy_rules
- runtime_calls
- policy_decisions
- audit_events

## Documentation automatique

Une fois le backend lancé :

```text
http://127.0.0.1:8000/docs
```

## Statut

Tâche 1.5 — Base PostgreSQL minimale.
