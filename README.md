# MCP Security Framework

Framework de securite et de gouvernance pour agents IA utilisant le Model Context Protocol.

## Objectif

Ce projet vise a ajouter une couche de controle autour des agents IA utilisant MCP.

L'objectif est de verifier, avant execution, si un agent IA est autorise a appeler un outil MCP avec des parametres donnes, dans un contexte donne.

Le framework couvre le cycle :

```text
Build -> Deploy -> Run -> Validate -> Audit
```

Le coeur du projet est le controle runtime :

```text
Agent IA -> MCP Proxy -> Moteur de decision -> Decision -> Serveur MCP
```

Le LLM propose un appel d'outil, mais la decision de securite est prise par le framework.

Docker n'est pas utilise dans le MVP local. Le projet est lance directement avec Python, Node.js et PostgreSQL afin de garder un environnement simple et controlable.

## Modules principaux

- Agent IA Python
- Adaptateur LLM
- MCP Proxy
- Moteur de decision runtime
- Inventaire MCP
- Backend FastAPI
- Frontend React
- Base PostgreSQL
- Modules Build Security, Deploy Security, Validation et Audit

## Structure du repository

```text
mcp-security-framework/
|-- backend/      API FastAPI
|-- frontend/     Interface React
|-- agent/        Agent IA Python et adaptateur LLM
|-- proxy/        MCP Proxy et logique runtime
|-- mcp-lab/      Serveurs MCP de test et donnees de demonstration
|-- policies/     Regles de securite YAML/JSON
|-- scanners/     Modules Semgrep, Trivy, GitLeaks, Prowler, Checkov
|-- reports/      Rapports generes localement
|-- docs/         Documentation locale du projet
|-- scripts/      Scripts de verification et de lancement local
|-- .env.example
|-- .gitignore
`-- README.md
```

## Etat actuel

Phase 1 - Architecture et environnement minimal.

La tache actuelle consiste a preparer l'environnement local du MVP :

- verification des dependances minimales ;
- scripts de lancement backend et frontend ;
- configuration d'exemple pour un lancement local ;
- repository centre sur le code, le README et la configuration utile.

Le backend complet, le frontend complet et la base de donnees seront implementes dans les taches suivantes.

## Dependances requises

Pour lancer la plateforme en local, il faut installer :

- Python 3.11+
- pip
- Node.js 20+
- npm
- PostgreSQL 15+
- Git

Les dependances de securite avancees seront ajoutees plus tard :

- Semgrep
- Trivy
- GitLeaks
- Checkov
- Prowler
- AWS CLI

## Verification de l'environnement

```bash
python scripts/check_dependencies.py
```

## Lancement local

### Backend

Windows :

```bat
scripts\start_backend.bat
```

Linux/macOS :

```bash
./scripts/start_backend.sh
```

### Frontend

Windows :

```bat
scripts\start_frontend.bat
```

Linux/macOS :

```bash
./scripts/start_frontend.sh
```

## Configuration

Les variables d'environnement attendues sont decrites dans :

```text
.env.example
```

Ne jamais mettre de vrais secrets dans le repository.

## Regles de securite initiales

Les regles initiales du framework sont definies dans :

```text
policies/default_rules.yaml
```

Elles preparent les decisions runtime : `ALLOW`, `BLOCK`, `WARN`, `LIMIT`, `ASK_APPROVAL` et `LOG_ONLY`.

## Statut

Phase 1 en cours - Backend minimal, PostgreSQL, routes API minimales et frontend React minimal en place.
