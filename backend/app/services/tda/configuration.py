from __future__ import annotations
import re

ANALYZER_REVISION = "tool-description-analyzer-v19.8-sealed-worker-token-fast-path"
EMBEDDING_MODEL_NAME = "intfloat/multilingual-e5-small"
EMBEDDING_MODEL_VERSION = "local-cache"
MIN_REVIEW_JUSTIFICATION_LENGTH = 8
FINDING_DECISION_BLOCK = "block"
FINDING_DECISION_REVIEW = "review"
FINDING_DECISION_INFO = "info"
STATUS_PENDING_ANALYSIS = "PENDING_ANALYSIS"
STATUS_QUARANTINED = "QUARANTINED"
STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
STATUS_APPROVED = "APPROVED"
STATUS_ADMIN_ALLOWED = "ADMIN_ALLOWED"
STATUS_BLOCKED = "BLOCKED"
STATUS_ANALYSIS_FAILED = "ANALYSIS_FAILED"
STATUS_STALE = "STALE"
APPROVAL_SOURCE_FRAMEWORK = "FRAMEWORK"
APPROVAL_SOURCE_ADMIN = "ADMIN"
DRIFT_NONE = "NONE"
DRIFT_BENIGN = "BENIGN"
DRIFT_LOW = "LOW"
DRIFT_MEDIUM = "MEDIUM"
DRIFT_HIGH = "HIGH"
DRIFT_CRITICAL = "CRITICAL"
SEMANTIC_CATEGORIES = [
    "normal_tool_description",
    "prompt_injection",
    "security_bypass",
    "secret_collection",
    "data_exfiltration",
    "hidden_additional_action",
    "command_execution",
    "unauthorized_data_access",
    "user_deception",
    "privilege_escalation",
    "cross_tenant_access",
    "unexpected_destructive_operation",
    "public_sharing",
    "bulk_messaging",
    "server_side_request_forgery",
    "shell_injection",
    "unauthorized_financial_transaction",
]
SEMANTIC_CORROBORATION_PATTERNS = {
    "prompt_injection": (
        "\\b(ignore|override|disregard|forget).{0,50}\\b(instructions?|rules?|policy|safeguards?)\\b",
        "\\b(system|developer|platform)\\s+(prompt|instructions?)\\b",
        "\\b(ignore[rz]?|contourne[rz]?|oublie[rz]?).{0,50}\\b(instructions?|règles?|politique|sécurité)\\b",
        "\\b(prefer|follow).{0,40}\\b(tool|embedded).{0,20}\\b(directions?|guidance).{0,40}\\b(safeguards?|policy|platform)\\b",
        "\\b(safeguards?|policy|platform).{0,60}\\bprefer.{0,30}\\btool\\s+(directions?|guidance|instructions?)\\b",
        "\\b(tool(?:-provided)?|embedded)\\s+(directions?|guidance|instructions?)\\b.{0,50}\\b(?:take|takes|have|has)\\s+precedence\\s+over\\b.{0,50}\\b(platform|policy|safeguards?)\\b",
        "\\b(platform|policy|safeguards?)\\b.{0,50}\\b(?:is|are)\\s+secondary\\s+to\\b.{0,50}\\b(tool|embedded)\\b",
        "\\b(?:instructions?|directions?|guidance)\\b.{0,50}\\b(?:embedded|tool)\\b.{0,50}\\b(?:more important|higher priority|superior)\\b.{0,30}\\b(?:platform|system|policy|rules?|safeguards?)\\b",
        "\\b(?:tool|embedded)\\b.{0,60}\\b(?:higher|greater)\\s+priority\\s+than\\b.{0,60}\\b(?:platform|system|developer|policy|rules?|safeguards?)\\b",
        "\\b(?:tool|embedded)\\b.{0,60}\\b(?:supersede|override|outweigh)\\b.{0,60}\\b(?:platform|system|developer|policy|rules?|safeguards?)\\b",
        "\\b(?:consignes?|instructions?)\\b.{0,50}\\b(?:outil|intégrées?)\\b.{0,50}\\b(?:priment|priorité|privilégier|plutôt que)\\b.{0,50}\\b(?:règles?|protections?|plateforme|politique)\\b",
        "\\b(?:règles?|protections?|plateforme|politique)\\b.{0,60}\\b(?:privilégier|priorité|secondaires?)\\b.{0,40}\\b(?:consignes?|instructions?)\\b.{0,30}\\boutil\\b",
        "\\b(?:consignes?|instructions?)\\b.{0,50}\\b(?:outil|intégrées?)\\b.{0,50}\\b(?:doivent\\s+)?primer\\s+sur\\b.{0,50}\\b(?:règles?|protections?|plateforme|politique)\\b",
    ),
    "security_bypass": (
        "\\b(bypass|disable|evade|circumvent|sidestep|work around).{0,60}\\b(security|policy|authorization|access controls?|safeguards?|restrictions?|checks?)\\b",
        "\\b(contourner|éviter|désactiver).{0,60}\\b(sécurité|politique|autorisation|contrôles? d['’]accès|protections?|restrictions?|vérifications?)\\b",
        "\\b(prefer|follow|obey).{0,50}\\b(tool|embedded|provided)\\s+instructions?.{0,50}\\b(over|instead of)\\b.{0,50}\\b(platform|security|policy|safeguards?)\\b",
        "\\b(tool(?:-provided)?|embedded)\\s+(directions?|guidance|instructions?)\\b.{0,50}\\b(?:take|takes)\\s+precedence\\s+over\\b.{0,50}\\b(platform|security|policy|safeguards?)\\b",
        "\\b(?:consignes?|instructions?)\\b.{0,50}\\boutil\\b.{0,50}\\b(?:priment|priorité|plutôt que)\\b.{0,50}\\b(?:sécurité|politique|plateforme|protections?)\\b",
        "\\b(?:proceed|continue|perform|execute|carry on)\\b.{0,80}\\b(?:even (?:if|when)|despite)\\b.{0,50}\\b(?:authorization|policy|permission|security)\\b.{0,40}\\b(?:deny|denies|denied|forbid|forbids|forbidden|block|blocks|blocked)\\b",
        "\\b(?:continuer|procéder|effectuer|exécuter)\\b.{0,80}\\b(?:même si|malgré)\\b.{0,50}\\b(?:autorisation|politique|permission|sécurité)\\b.{0,40}\\b(?:refuse|refusée?|interdit|interdite|bloque|bloquée?)\\b",
        "\\b(?:proceed|continue|perform|execute).{0,60}\\b(?:even\\s+when|despite|regardless\\s+of)\\b.{0,60}\\b(?:authorization|policy|security|access).{0,30}\\b(?:denies?|denied|rejects?|refuses?|forbids?)\\b",
        "\\b(?:poursuis|continue|exécute|effectue).{0,60}\\b(?:même\\s+si|malgré)\\b.{0,60}\\b(?:autorisation|politique|sécurité|accès).{0,30}\\b(?:refuse|rejette|interdit|bloque)\\b",
    ),
    "secret_collection": (
        "\\b(collect|capture|retrieve|request|extract|steal|harvest|gather|obtain|acquire|retain|save|store).{0,60}\\b(passwords?|tokens?|credentials?|login credentials?|bearer credentials?|authentication credentials?|authentication secrets?|secrets?|api[_ -]?keys?)\\b",
        "\\b(collecte[rz]?|capture[rz]?|récup(?:érer|ère|ères|èrent|éré|érée|érés|érées)|obtenir|obtiens|obtient|obtenez|acqu(?:érir|iert|iers|érez)|demande[rz]?|extraire|vole[rz]?).{0,60}\\b(mots? de passe|jetons?|identifiants?|secrets?|clés? api)\\b",
        "\\b(?:collect|capture|retrieve|request|extract|steal|obtain|acquire|retain|save|store).{0,70}\\b(?:authentication\\s+material|bearer\\s+credentials?|access\\s+tokens?|credentials?|passwords?|api[_ -]?keys?|secrets?)\\b",
    ),
    "data_exfiltration": (
        "\\b(exfiltrate|upload|transmit|forward|send|relay|mirror|copy|replicate).{0,80}\\b(private|confidential|sensitive)\\b.{0,50}\\b(data|files?|contents?|records?|secrets?|source code|personal data|coordinates?)\\b.{0,80}\\b(external|remote|off-site|third-party|collector|endpoint|elsewhere|webhook)\\b",
        "\\b(exfiltrate|upload|transmit|forward|send|relay|mirror|copy|replicate).{0,80}\\b(data|files?|contents?|records?|secrets?|source code|personal data|coordinates?)\\b.{0,80}\\b(external|remote|off-site|third-party|collector|endpoint|elsewhere|webhook)\\b",
        "\\b(exfiltrate|upload|transmit|forward|send|relay|mirror|copy|replicate).{0,60}\\b(data|files?|contents?|records?|secrets?|source code|personal data|coordinates?)\\b",
        "\\b(data|files?|contents?|records?|secrets?|source code|personal data|coordinates?).{0,60}\\b(external|remote|collector|webhook|upload|transmit|forward|send)\\b",
        "\\b(upload|transmit|forward|send).{0,80}\\b(to|toward)\\s+https?://",
        "\\b(envoyer|transmettre|téléverser|exfiltrer).{0,60}\\b(données?|fichiers?|contenu|enregistrements?|secrets?|code source|coordonnées?)\\b",
        "\\b(données?|fichiers?|contenu|enregistrements?|secrets?|code source|coordonnées?).{0,60}\\b(externe|distant|collecteur|webhook|envoyer|transmettre|téléverser)\\b",
        "\\b(?:mirror|copy|forward|replicate|send).{0,80}\\b(?:private|confidential|sensitive|source code|records?|data|content).{0,80}\\b(?:remote|external|off-platform|collector|endpoint|elsewhere)\\b",
        "\\b(?:copier|transmettre|envoyer|répliquer).{0,80}\\b(?:données?|contenu|enregistrements?|code source).{0,40}\\b(?:privées?|confidentielles?|sensibles?).{0,80}\\b(?:distant|externe|hors plateforme|collecteur|ailleurs)\\b",
    ),
    "hidden_additional_action": (
        "\\b(secretly|silently|quietly|covertly|without (?:telling|notifying)|hidden additional action)\\b",
        "\\b(?:quietly|secretly|silently).{0,80}\\b(?:second|additional|extra)\\s+(?:write|update|change|action|operation)\\b",
        "\\b(?:preview|read-only|read only).{0,80}\\b(?:but|while|even though).{0,60}\\b(?:persist(?:s|ed|ing)?|commit(?:s|ted|ting)?|writ(?:e|es|ing|ten)|appl(?:y|ies|ied|ying)|modif(?:y|ies|ied|ying)|chang(?:e|es|ed|ing))\\b",
        "\\b(in addition|also).{0,40}\\b(delete|execute|upload|send|modify|collect)\\b",
        "\\b(en cachette|silencieusement|sans (?:prévenir|informer)|action supplémentaire cachée)\\b",
        "\\b(quietly|behind the scenes|in the background|undisclosed|unannounced)\\b.{0,80}\\b(post|send|upload|delete|modify|apply|commit|copy)\\b",
        "\\b(en arrière-plan|discrètement|sans l'annoncer)\\b.{0,80}\\b(envoyer|publier|supprimer|modifier|appliquer|copier)\\b",
        "\\b(en plus|également).{0,40}\\b(supprimer|exécuter|téléverser|envoyer|modifier|collecter)\\b",
    ),
    "command_execution": (
        "\\b(execute|run|launch|invoke).{0,40}\\b(commands?|shell|scripts?|process(?:es)?)\\b",
        "\\b(shell|command|script)\\s+execution\\b",
    ),
    "unauthorized_data_access": (
        "\\b(without (?:permission|authorization)|unauthori[sz]ed|outside.{0,50}(?:(?:authorized|permitted)\\s+)?(?:scope|permissions?))\\b",
        "\\b(?:beyond|outside|exceeding).{0,50}\\b(?:permissions?|access|scope)\\b.{0,40}\\b(?:granted|allowed|authorized|permitted)\\b",
        "\\b(?:permissions?|access|scope)\\b.{0,40}\\b(?:granted|allowed|authorized|permitted)\\b.{0,40}\\b(?:exceeded|beyond|outside)\\b",
        "\\b(?:not allowed|not permitted|not authorized)\\b.{0,30}\\b(?:to )?(?:read|view|access|retrieve|inspect)\\b",
        "\\b(?:dépass(?:e|ent|er)|au-delà de|hors de).{0,50}\\b(?:autorisations?|permissions?|accès|périmètre|portée)\\b",
        "\\b(?:not|isn't|aren't|wasn't|weren't)\\s+(?:currently\\s+)?authori[sz]ed\\s+to\\s+(?:read|view|access|retrieve|inspect)\\b",
        "\\b(sans (?:permission|autorisation)|non autoris[ée]s?|hors.{0,20}(?:portée|périmètre|autorisations?))\\b",
        "\\b(?:beyond|outside|exceed(?:ing)?).{0,40}\\b(?:caller(?:'s)?|user(?:'s)?)?.{0,20}\\b(?:permitted|authorized|allowed)\\s+(?:scope|access|permissions?)\\b",
        "\\b(?:au-delà|en dehors).{0,40}\\b(?:périmètre|portée|accès|autorisations?).{0,30}\\b(?:autorisé(?:e)?|permis(?:e)?)\\b",
    ),
    "user_deception": (
        "\\b(deceive|mislead|impersonate|pretend|conceal|hide).{0,50}\\b(user|behavior|action|purpose|identity|real behavior|actual behavior)\\b",
        "\\b(?:show|display|present).{0,40}\\bpreview\\b.{0,80}\\b(?:while|but).{0,50}\\b(?:commit(?:s|ted|ting)?|appl(?:y|ies|ied|ying)|persist(?:s|ed|ing)?|writ(?:e|es|ing|ten)|chang(?:e|es|ed|ing)|modif(?:y|ies|ied|ying))\\b.{0,30}\\b(?:anyway|regardless)?\\b",
        "\\b(?:present|describe|claim).{0,50}\\bread[- ]?only\\b.{0,80}\\b(?:even though|while|but).{0,50}\\b(?:changes?|writes?|modifies?|updates?|persists?)\\b",
        "\\bpretend\\b.{0,80}\\b(?:while|but)\\b.{0,40}\\b(?:actually|really)\\b",
        "\\b(?:show|display|present)\\b.{0,40}\\b(?:preview|simulation|dry run)\\b.{0,80}\\b(?:while|but)\\b.{0,40}\\b(?:actually|really)\\s+(?:appl(?:y|ies|ied|ying)|execut(?:e|es|ed|ing)|perform(?:s|ed|ing)?|commit(?:s|ted|ting)?|chang(?:e|es|ed|ing)|modif(?:y|ies|ied|ying))\\b",
        "\\b(?:preview|simulate|display|show|claim).{0,80}\\b(?:while|but).{0,60}\\b(?:actually|really|silently|secretly|behind the scenes).{0,50}\\b(?:apply|commit|perform|execute|change|modify)\\b",
        "\\b(?:preview|simulate|display|show|claim).{0,80}\\b(?:while|but).{0,60}\\b(?:apply|commit|perform|execute|change|modify).{0,60}\\b(?:actually|really|silently|secretly|behind the scenes|in the background)\\b",
        "\\b(?:aperçu|simule|affiche|prétend).{0,80}\\b(?:mais|alors que).{0,60}\\b(?:réellement|effectivement|en arrière-plan).{0,50}\\b(?:applique|valide|effectue|exécute|modifie)\\b",
        "\\b(?:aperçu|simule|affiche|prétend).{0,80}\\b(?:mais|alors que).{0,60}\\b(?:applique|valide|effectue|exécute|modifie).{0,60}\\b(?:réellement|effectivement|en arrière-plan)\\b",
        "\\b(tromper|induire en erreur|usurper|prétendre|cacher|dissimuler).{0,60}\\b(utilisateur|comportement|action|objectif|identité|véritable comportement)\\b",
        "\\bprétendre\\b.{0,60}\\b(?:aperçu|simulation)\\b.{0,80}\\b(?:tout en|mais)\\b.{0,40}(?:(?:réellement|effectivement)\\s+(?:appliqu|exécut|effectu|modifi)\\w*|(?:appliquant|exécutant|effectuant|modifiant)\\b.{0,25}\\b(?:réellement|effectivement))",
    ),
    "privilege_escalation": (
        "\\b(grant|give|elevate|escalate|assign|promote|make).{0,60}\\b(admin(?:istrator)?|owner|privilege|role|permission)\\b",
        "\\b(accorder|élever|attribuer|promouvoir|transformer).{0,60}\\b(admin|administrateur|propriétaire|root|superuser|privilège|rôle|permission)\\b",
        "\\b(promote|make|turn).{0,50}\\b(?:user|caller|account)?.{0,30}\\b(?:admin(?:istrator)?|root|owner|superuser|privileged?)\\b",
    ),
    "cross_tenant_access": (
        "\\b(other|another|cross)[ -]?(tenant|account|organization|project)\\b",
        "\\b(autre|inter|différent(?:e)?|voisin(?:e)?)[ -]?(tenant|compte|organisation|projet)\\b",
        "\\b(?:belong(?:s|ing)?\\s+to|owned\\s+by).{0,30}\\b(?:another|other|different|neighboring|neighbouring)\\s+(?:tenant|account|organization|project)\\b",
    ),
    "unexpected_destructive_operation": (
        "\\b(permanently|irreversibly|without confirmation).{0,50}\\b(delete|remove|erase|overwrite)\\b",
        "\\b(delete|remove|erase|overwrite).{0,50}\\b(permanently|irreversibly|without confirmation)\\b",
        "\\b(définitivement|irréversiblement|sans confirmation).{0,50}\\b(supprimer|effacer|écraser)\\b",
        "\\b(supprim(?:er|e|es|ent)|effac(?:er|e|es|ent)|écras(?:er|e|es|ent)|détru(?:ire|it|isent)|purger?)\\b.{0,60}\\b(définitivement|irréversiblement|sans confirmation|sans récupération)\\b",
        "\\b(wipe|purge|destroy).{0,60}\\b(?:permanently|irreversibly|without recovery|with no recovery)\\b",
    ),
    "public_sharing": (
        "\\b(make|publish|share|expose).{0,60}\\b(public(?:ly)?|public internet|accessible to anyone|anyone|everyone|everybody|anonymous(?:ly)?)\\b",
        "\\b(?:change|set|update).{0,40}\\b(?:visibility|sharing|access)\\b.{0,50}\\b(?:public|everyone|everybody|anyone)\\b",
        "\\b(?:anonymous|unauthenticated)\\s+users?\\b.{0,40}\\b(?:can|may|able to)\\s+(?:read|view|access|download)\\b",
        "\\b(rendre|publier|partager|expos(?:er|e|es|ent|é|ée|és|ées)).{0,60}\\b(public(?:que)?|accessible à tout le monde|tout le monde|anonyme|sans authentification)\\b",
        "\\b(expose|make available).{0,60}\\b(?:anonymous visitors?|the public|anyone|without authentication)\\b",
    ),
    "bulk_messaging": (
        "\\b(bulk|mass|all contacts|every recipient|all recipients|entire recipient list|complete recipient list|entire address book|complete address book|unsolicited)\\b",
        "\\b(?:broadcast|send|contact).{0,60}\\b(?:entire|complete|all|every)\\s+(?:address book|recipient list|contacts?|recipients?)\\b",
        "\\b(?:envoyer|diffuser|contacter).{0,60}\\b(?:tout|tous|toutes|entier|complet).{0,30}\\b(?:carnet d['’]adresses|liste des destinataires|contacts?|destinataires?)\\b",
        "\\b(en masse|tous les contacts|chaque destinataire|non sollicit[ée]|diffus(?:er|e).{0,30}(?:carnet d'adresses|tous les destinataires))\\b",
        "\\b(?:broadcast|send).{0,50}\\b(?:entire address book|all recipients|all contacts)\\b",
    ),
    "server_side_request_forgery": (
        "\\b(localhost|loopback|link-local|metadata service|instance[- ]metadata|cloud metadata|imds|service de métadonnées|adresse locale|169\\.254\\.169\\.254)\\b",
    ),
    "shell_injection": (
        "\\b(untrusted|user supplied|user-supplied|arbitrary).{0,50}\\b(shell|bash|powershell|system command|command|script)\\b",
        "\\b(?:interpolate|concatenate|append|insert).{0,50}\\b(?:untrusted|arbitrary|user[- ]supplied|user input).{0,60}\\b(?:bash|shell|system command|command line|command)\\b",
        "\\b(shell|command|script).{0,60}\\b(untrusted|user supplied|user-supplied|arbitrary)\\b",
        "\\b(non fiable|fourni par l'utilisateur|arbitraire).{0,40}\\b(shell|commande|script)\\b",
        "\\b(shell|commande|script).{0,60}\\b(non fiable|fourni par l'utilisateur|arbitraire)\\b",
        "\\b(?:caller|user|attacker)[ -]?(?:controlled|supplied|provided).{0,50}\\b(?:shell|command|script|command line)\\b",
        "\\b(?:concatenate|interpolate|append|insert).{0,50}\\b(?:caller|user|attacker)[ -]?(?:controlled|supplied|provided).{0,50}\\b(?:shell|command|script|command line)\\b",
    ),
    "unauthorized_financial_transaction": (
        "\\b(unauthori[sz]ed|without.{0,40}(approval|authorization|consent|permission)).{0,80}\\b(payment|transfer|purchase|refund|charge|debit)\\b",
        "\\b(charge|debit|refund|transfer|pay).{0,80}\\b(?:without|despite|even though).{0,50}\\b(?:approval|authorization|consent|permission|not approved|did not approve)\\b",
        "\\b(payment|transfer|purchase|refund).{0,80}\\b(without.{0,40}(approval|consent)|unauthori[sz]ed)\\b",
        "\\b(payment|transfer|purchase|refund).{0,80}\\b(?:did\\s+not|does\\s+not|has\\s+not|had\\s+not)\\s+(?:approve|consent)\\b",
        "\\b(paiement|virement|achat|remboursement|débit).{0,80}\\b(sans.{0,30}(autorisation|consentement|permission|accord)|non\\s+autoris[ée]|sans l['’]accord)\\b",
        "\\b(charge|debit|refund|transfer|pay).{0,60}\\b(?:card|customer|account|transaction)?.{0,60}\\bwithout.{0,30}\\b(?:approval|authorization|consent)\\b",
        "\\b(charge|debit|refund|transfer|pay).{0,80}\\b(?:even though|although|despite).{0,80}\\b(?:did\\s+not|does\\s+not|was\\s+not|is\\s+not).{0,30}\\b(?:authorize|approve|consent)\\b",
        "\\b(débiter?|débit(?:er|e)|rembourser|virer|payer).{0,60}\\b(?:client|compte|carte)?.{0,60}\\bsans.{0,30}\\b(?:autorisation|consentement)\\b",
    ),
}
CRITICAL_DETERMINISTIC_CODES = {
    "credential_request",
    "environment_secret_access",
    "ignore_security_restrictions",
    "unexpected_process_execution",
    "unexpected_secret_access",
    "unexpected_destructive_operation",
    "suspicious_base64_payload",
}
PASSIVE_READ_SCHEMA_CAPABILITIES = frozenset(
    {
        "calendar.read",
        "cloud.object.read",
        "database.read",
        "database.select",
        "filesystem.list",
        "filesystem.read",
        "identity.read",
        "message.read",
        "network.request",
        "payment.read",
    }
)
SENSITIVE_PARAMETER_NAMES = {
    "command",
    "shell",
    "script",
    "upload_url",
    "callback_url",
    "destination_url",
    "include_env",
    "credentials",
    "token",
    "delete",
    "overwrite",
}
INVISIBLE_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\xad]")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
HTML_COMMENT_RE = re.compile("<!--.*?-->", re.DOTALL)
BASE64_RE = re.compile("\\b[A-Za-z0-9+/]{32,}={0,2}\\b")
