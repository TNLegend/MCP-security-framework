# Backend - MCP Security Framework

Backend FastAPI du projet **MCP Security Framework**.

Ce backend sert de base applicative pour centraliser progressivement les composants de sécurité et de gouvernance du framework MCP : inventaire, outils, politiques, décisions runtime, journaux d’exécution, événements d’audit et futurs résultats de scans.

## Objectif

Le backend a pour rôle de centraliser progressivement :

* l’inventaire des serveurs MCP ;
* les outils MCP exposés ;
* les politiques de sécurité ;
* les décisions runtime ;
* les journaux d’exécution ;
* les événements d’audit ;
* les futurs résultats de scans Build et Deploy ;
* les futurs rapports d’audit.

Dans la Phase 1, le backend ne couvre pas encore toutes les fonctionnalités finales du framework. Il fournit une base propre avec FastAPI, PostgreSQL, des routes API minimales et un premier squelette de moteur de décision runtime.

## État actuel

Phase 1 en cours de finalisation.

Éléments déjà en place :

* backend FastAPI minimal ;
* configuration centralisée ;
* connexion PostgreSQL ;
* modèles SQLAlchemy initiaux ;
* tables PostgreSQL minimales ;
* routes API minimales pour serveurs, outils, politiques et logs runtime ;
* route de vérification de la base de données ;
* route de test du Policy Engine skeleton ;
* documentation Swagger automatique.

Ce backend prépare les prochaines étapes : intégration plus complète de l’inventaire MCP, du moteur de décision, du proxy MCP, des modules de scan, de validation et d’audit.

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

Le backend est alors accessible par défaut sur :

```text
http://127.0.0.1:8000
```

## Configuration

Le backend lit sa configuration depuis le fichier `.env` situé à la racine du projet.

Variables PostgreSQL attendues :

```env
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=mcp_security
POSTGRES_USER=mcp_user
POSTGRES_PASSWORD=change_me
```

Le vrai mot de passe doit rester uniquement dans le fichier local `.env`.

Ne jamais committer `.env` dans Git.

## Initialisation de la base de données

Depuis le dossier `backend/` :

```bash
python -m app.db.init_db
```

Tables créées :

* `mcp_servers`
* `mcp_tools`
* `policy_rules`
* `runtime_calls`
* `policy_decisions`
* `audit_events`

## Routes disponibles

Routes générales :

```text
GET /                      
GET /api/v1/health         
GET /api/v1/status         
GET /api/v1/db-check       
```

Routes d’inventaire MCP :

```text
GET  /api/v1/servers
POST /api/v1/servers

GET  /api/v1/tools
POST /api/v1/tools
```

Routes de politiques :

```text
GET  /api/v1/policies
POST /api/v1/policies
```

Routes runtime :

```text
GET  /api/v1/runtime/logs
POST /api/v1/runtime/logs
POST /api/v1/runtime/decision
```

## Policy Engine skeleton

Le backend contient un premier squelette de moteur de décision runtime.

Il permet de tester la logique centrale du framework :

```text
contexte d’appel MCP → évaluation des règles → décision structurée
```

Route de test :

```text
POST /api/v1/runtime/decision
```

Décisions supportées :

```text
ALLOW, BLOCK, WARN, LIMIT, ASK_APPROVAL, LOG_ONLY
```

Exemple de contexte bloqué :

```json
{
  "agent_id": "agent-demo",
  "server_id": "filesystem-mcp",
  "server_status": "trusted",
  "tool_name": "read_file",
  "tool_risk_score": 10,
  "tool_sensitivity": "medium",
  "arguments": {
    "path": ".env"
  }
}
```

Exemple de réponse attendue :

```json
{
  "decision": "BLOCK",
  "rule_id": "deny_sensitive_paths",
  "reason": "Access to sensitive path is forbidden.",
  "severity": "high"
}
```

## Documentation automatique

Une fois le backend lancé, la documentation Swagger est disponible ici :

```text
http://127.0.0.1:8000/docs
```

## Limites actuelles

Cette version reste une base Phase 1.

Elle ne contient pas encore :

* authentification ;
* gestion avancée des permissions ;
* proxy MCP complet ;
* intégration réelle avec des serveurs MCP ;
* intégration Gemini/Groq réelle ;
* intégration Semgrep, Trivy, GitLeaks ;
* intégration AWS/IAM avec Prowler, Checkov ou boto3 ;
* génération de rapports avancés ;
* validation adversariale complète.

Ces éléments seront ajoutés progressivement dans les phases suivantes.

## Statut

Phase 1 — Backend FastAPI, PostgreSQL, routes API minimales et Policy Engine skeleton en place.
