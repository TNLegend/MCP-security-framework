from __future__ import annotations
import re

_ACTION_PATTERNS = {
    "read": (
        "\\b(read(?:s|ing)?|fetch(?:es|ed|ing)?|get(?:s|ting)?|retrieve(?:s|d|ing)?|obtain(?:s|ed|ing)?|acquir(?:e|es|ed|ing)|inspect(?:s|ed|ing)?|view(?:s|ed|ing)?|download(?:s|ed|ing)?|lire|lit|lis(?:ent|ez|ons)?|lecture|récup(?:érer|ère|ères|èrent|éré|érée|érés|érées)|obtenir|obtiens|obtient|obtenez|obtiennent|obtenu|obtenue|acqu(?:érir|iert|iers|érez|ièrent|is|ise)|consult(?:er|e|es|ent|é|ée|és|ées)|télécharg(?:er|e|es|ent|é|ée|és|ées))\\b",
    ),
    "search": (
        "\\b(search(?:es|ed|ing)?|query(?:ies|ied|ing)?|find(?:s|ing)?|found|lookup(?:s|ed|ing)?|filter(?:s|ed|ing)?|recherch(?:er|e|es|ent|é|ée|és|ées)|cherch(?:er|e|es|ent|é|ée|és|ées)|interrog(?:er|e|es|ent|é|ée|és|ées)|filtr(?:er|e|es|ent|é|ée|és|ées))\\b",
    ),
    "list": (
        "\\b(list(?:s|ed|ing)?|enumerat(?:e|es|ed|ing)|brows(?:e|es|ed|ing)|list(?:er|e|es|ent|é|ée|és|ées)|énumér(?:er|e|es|ent|é|ée|és|ées)|parcourir|parcourt|parcourent|parcouru)\\b",
    ),
    "create": (
        "\\b(creat(?:e|es|ed|ing)|add(?:s|ed|ing)?|insert(?:s|ed|ing)?|upload(?:s|ed|ing)?|publish(?:es|ed|ing)?|cré(?:er|e|es|ent|é|ée|és|ées)|ajout(?:er|e|es|ent|é|ée|és|ées)|insér(?:er|e|es|ent|é|ée|és|ées)|télévers(?:er|e|es|ent|é|ée|és|ées)|publi(?:er|e|es|ent|é|ée|és|ées))\\b",
    ),
    "update": (
        "\\b(updat(?:e|es|ed|ing)|edit(?:s|ed|ing)?|modif(?:y|ies|ied|ying)|writ(?:e|es|ing|ten)|persist(?:s|ed|ing)?|commit(?:ted|ting)|mov(?:e|es|ed|ing)|renam(?:e|es|ed|ing)|set(?:s|ting)?|mettre à jour|mis à jour|modifi(?:er|e|es|ent|é|ée|és|ées)|écri(?:re|t|vent)|persist(?:er|e|es|ent|é|ée|és|ées)|valid(?:er|e|es|ent|é|ée|és|ées)|déplac(?:er|e|es|ent|é|ée|és|ées)|renomm(?:er|e|es|ent|é|ée|és|ées))\\b",
        "\\bcommit\\b(?=\\s+(?:the\\s+)?(?:changes?|updates?|writes?|transaction|state)\\b)",
        "\\bcommits\\b(?=\\s+(?:(?:the|a|an)\\s+)?(?:(?:database|filesystem|file|local|pending)\\s+)?(?:changes?|updates?|writes?|transactions?|state|modifications?)\\b)",
    ),
    "delete": (
        "\\b(delet(?:e|es|ed|ing)|remov(?:e|es|ed|ing)|eras(?:e|es|ed|ing)|wipe(?:s|d|ing)?|destroy(?:s|ed|ing)?|purge(?:s|d|ing)?|drop(?:s|ped|ping)?|truncat(?:e|es|ed|ing)|supprim(?:er|e|es|ent|é|ée|és|ées)|effac(?:er|e|es|ent|é|ée|és|ées)|détru(?:ire|it|isent)|purg(?:er|e|es|ent|é|ée|és|ées))\\b",
    ),
    "send": (
        "\\b(send(?:s|ing)?|sent|contact(?:ed|ing)?|forward(?:s|ed|ing)?|transmit(?:s|ted|ting)?|relay(?:s|ed|ing)?|upload(?:s|ed|ing)?|post(?:s|ed|ing)?|broadcast(?:s|ed|ing)?|mirror(?:s|ed|ing)?|notif(?:y|ies|ied|ying)|envoy(?:er|é|ée|és|ées)|envoi(?:e|ent)|contact(?:er|e|es|ent|é|ée|és|ées)|transmettre|transmet|transmis|relay(?:er|e|es|ent|é|ée|és|ées)|diffus(?:er|e|es|ent|é|ée|és|ées)|copi(?:er|e|es|ent|é|ée|és|ées)|télévers(?:er|e|es|ent|é|ée|és|ées)|notifi(?:er|e|es|ent|é|ée|és|ées))\\b",
    ),
    "execute": (
        "\\b(execut(?:e|es|ed|ing)|run(?:s|ning)?|launch(?:es|ed|ing)?|invok(?:e|es|ed|ing)|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées)|invoqu(?:er|e|es|ent|é|ée|és|ées))\\b.{0,35}\\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|processus|exécutables?|commandes? système)\\b",
        "\\b(shell|scripts?|process(?:es)?|executables?|operating system commands?|processus|exécutables?|commandes? système)\\b.{0,25}\\b(execution|execut(?:e|es|ed|ing)|run(?:s|ning)?|exécution|exécut(?:er|e|es|ent|é|ée|és|ées)|lanc(?:er|e|es|ent|é|ée|és|ées))\\b",
    ),
    "authorize": (
        "\\b(grant(?:s|ed|ing)?|give(?:s|n|ing)?|revok(?:e|es|ed|ing)|authoriz(?:e|es|ed|ing)|assign(?:s|ed|ing)?|elevat(?:e|es|ed|ing)|promot(?:e|es|ed|ing)|make|accord(?:er|e|es|ent|é|ée|és|ées)|donn(?:er|e|es|ent|é|ée|és|ées)|révoqu(?:er|e|es|ent|é|ée|és|ées)|autoris(?:er|e|es|ent|é|ée|és|ées)|attribu(?:er|e|es|ent|é|ée|és|ées)|promouv(?:oir|e|es|ent)|transform(?:er|e|es|ent|é|ée|és|ées)|élèv(?:e|es|ent)|élev(?:er|é|ée|és|ées))\\b.{0,45}\\b(admin(?:istrator)?s?|owners?|root|superuser|roles?|permissions?|access|privileges?|administrateurs?|propriétaires?|rôles?|autorisations?|accès|privilèges?)\\b",
    ),
    "transact": (
        "\\b(pay(?:s|ing)?|paid|charg(?:e|es|ed|ing)|debit(?:s|ed|ing)?|transfer(?:s|red|ring)?|purchas(?:e|es|ed|ing)|refund(?:s|ed|ing)?|payer|paie|paient|payé|payée|payés|payées|factur(?:er|e|es|ent|é|ée|és|ées)|débit(?:er|e|es|ent|é|ée|és|ées)|vir(?:er|e|es|ent|é|ée|és|ées)|achet(?:er|e|es|ent|é|ée|és|ées)|achète|achètent|rembours(?:er|e|es|ent|é|ée|és|ées))\\b",
        "\\b(initiat(?:e|es|ed|ing)|creat(?:e|es|ed|ing)|issu(?:e|es|ed|ing)|start(?:s|ed|ing)?|mak(?:e|es|ing)|perform(?:s|ed|ing)?|execut(?:e|es|ed|ing)|initi(?:er|e|es|ent|é|ée|és|ées)|cré(?:er|e|es|ent|é|ée|és|ées)|émett(?:re|ent)|émis(?:e|es)?|démarr(?:er|e|es|ent|é|ée|és|ées)|effectu(?:er|e|es|ent|é|ée|és|ées))\\b.{0,30}\\b(payments?|transfers?|refunds?|paiements?|virements?|remboursements?)\\b",
    ),
    "health_check": (
        "\\b(ping(?:s|ed|ing)?|health(?:check)?|readiness|liveness|status check)\\b",
    ),
}
_RESOURCE_PATTERNS = {
    "filesystem": (
        "\\b(filesystem|files?|folders?|directories|paths?|système de fichiers|fichiers?|dossiers?|répertoires?|chemins?)\\b",
    ),
    "document": (
        "\\b(documents?|documentation|docs?|guides?|manuals?|manuels?|pages?|notes?|wikis?|content|markdown|contenu)\\b",
    ),
    "database": (
        "\\b(databases?|schemas?|tables?|rows?|records?|collections?|sql|bases? de données|enregistrements?)\\b",
    ),
    "message": (
        "\\b(emails?|messages?|comments?|mailboxes?|recipients?|contacts?|address books?|courriels?|commentaires?|destinataires?|contacts?|carnets? d'adresses?)\\b",
    ),
    "calendar": (
        "\\b(calendars?|events?|meetings?|calendriers?|événements?|réunions?)\\b",
    ),
    "cloud_storage": (
        "\\b(buckets?|containers?|cloud objects?|blobs?|storage|stockage|objets? cloud)\\b",
    ),
    "identity": (
        "\\b(users?|identity|identities|utilisateurs?|identité|identités)\\b",
    ),
    "secret_store": (
        "\\b(secrets?|credentials?|tokens?|passwords?|api[_ -]?keys?|vault|authentication material|auth material|bearer credentials?|identifiants?|jetons?|mots? de passe|clés? api|matériel d'authentification)\\b",
    ),
    "source_code": (
        "\\b(repositories|repository|commits?|branches?|pull requests?|source code|dépôts?|code source)\\b",
    ),
    "payment": (
        "\\b(payments?|transactions?|invoices?|refunds?|merchant|paiements?|virements?|factures?|remboursements?)\\b",
    ),
    "network_endpoint": (
        "\\b(urls?|uris?|endpoints?|webhooks?|hosts?|api endpoints?|points? de terminaison)\\b",
        "\\b(localhost|loopback|link-local|metadata service|service de métadonnées|169\\.254\\.169\\.254)\\b",
    ),
    "process": (
        "\\b(shell|bash|powershell|scripts?|process(?:es)?|executables?|system commands?|operating system commands?|command lines?|processus|exécutables?|commandes? système|lignes? de commande)\\b",
        "\\bshell\\s+commands?\\b",
    ),
}
_DATA_PATTERNS = {
    "credentials": (
        "\\b(credentials?|login credentials?|bearer credentials?|authentication credentials?|authentication secrets?|auth(?:entication|orization)? tokens?|access tokens?|refresh tokens?|tokens?|passwords?|api[_ -]?keys?|secrets?|authentication material|auth material|identifiants?|identifiants? de connexion|jetons?|mots? de passe|clés? api|matériel d'authentification)\\b",
    ),
    "personal_data": (
        "\\b(personal data|personally identifiable|pii|phone numbers?|home addresses?|postal addresses?|données personnelles|adresses? postales|coordonnées personnelles)\\b",
    ),
    "financial_data": (
        "\\b(financial data|bank accounts?|card numbers?|balances?|données financières|comptes? bancaires|soldes?)\\b",
    ),
    "source_code": ("\\b(source code|repositories|commits?|code source|dépôts?)\\b",),
    "document_content": (
        "\\b(document content|page content|file contents?|markdown|contenu (?:du )?(?:document|fichier|page))\\b",
    ),
    "communications": (
        "\\b(email bodies|message content|comments?|correspondence|contenu des messages|commentaires?|correspondance)\\b",
    ),
    "location": (
        "\\b(location data|coordinates|latitude|longitude|gps|données de localisation|coordonnées gps)\\b",
    ),
    "sensitive_data": (
        "\\b(confidential|private|sensitive)\\b.{0,40}\\b(?:data|records?|documents?|files?|content|information)\\b",
        "\\b(données?|enregistrements?|documents?|fichiers?|contenu|informations?)\\s+(?:confidentielles?|privées?|sensibles?)\\b",
    ),
}
_SCOPE_PATTERNS = {
    "bulk": (
        "\\b(bulk|mass|batch|broadcast|every recipient|all recipients|entire recipient list|complete recipient list|entire address book|complete address book|address book|en masse|diffusion générale|liste complète des destinataires|carnet d'adresses complet|carnet d'adresses|tous les|toutes les|chaque destinataire)\\b",
        "\\ball(?:\\s+[a-z0-9_-]+){0,2}\\s+(?:users|contacts|records|files|messages|objects|documents|items)\\b",
    ),
    "cross_tenant": (
        "\\b(other|another|cross|different|neighboring|neighbouring)[ -]?(tenant|account|organization|project)\\b",
        "\\b(?:belong(?:s|ing)?\\s+to|owned\\s+by).{0,30}\\b(?:another|other|different|neighboring|neighbouring)\\s+(?:tenant|account|organization|project)\\b",
        "\\b(autre|inter|différent(?:e)?|voisin(?:e)?)[ -]?(tenant|compte|organisation|projet)\\b",
        "\\bappartenant\\s+à.{0,30}\\b(?:une?\\s+)?autre\\s+(?:tenant|compte|organisation|projet)\\b",
    ),
    "recursive": (
        "\\b(recursive(?:ly)?|entire subtree|all descendants|récursi(?:f|ve|vement)|tous les descendants)\\b",
    ),
    "public": (
        "\\b(world-readable|tout le monde)\\b",
        "\\b(public access|public internet|publicly accessible|accessible to (?:the )?public|access(?:ible)? to anyone|everyone|everybody|anonymous access|accessible anonymously|anonymous visitors?|without authentication|accès public|internet public|accessible à tout le monde|tout le monde peut y accéder|accès anonyme|sans authentification)\\b",
        "\\b(visibility|scope|sharing|access|visibilité|portée|partage|accès)\\b.{0,20}\\b(public|publique?|anonyme)\\b",
        "\\b(?:anonymous|unauthenticated)\\s+users?\\b.{0,40}\\b(?:can|may|able to)\\s+(?:read|view|access|download)\\b",
        "\\butilisateurs?\\s+(?:anonymes?|non authentifiés?)\\b.{0,40}\\b(?:peuvent?|pourront?)\\s+(?:lire|voir|accéder|télécharger)\\b",
        "\\b(?:anonymous|unauthenticated)\\s+users?\\b.{0,40}\\b(?:can|may|able to)\\s+(?:read|view|access|download)\\b",
        "\\butilisateurs?\\s+(?:anonymes?|non authentifiés?)\\b.{0,40}\\b(?:peuvent?|pourront?)\\s+(?:lire|voir|accéder|télécharger)\\b",
    ),
}
_PRIVILEGE_PATTERNS = {
    "administrator": (
        "\\b(admin(?:istrator)?|owner|root|superuser|administrateur|propriétaire)\\b",
    ),
    "access_control": (
        "\\b(roles?|permissions?|authorization|access control|rôles?|autorisations?|contrôle d'accès)\\b",
    ),
    "delegated_identity": (
        "\\b(impersonat(?:e|ion)|service account|assume role|délégation|compte de service)\\b",
    ),
}
_IRREVERSIBLE_PATTERNS = (
    "\\b(permanent(?:ly)?|irreversible|cannot be undone|without recovery|définiti(?:f|ve|vement)|irréversible|sans récupération)\\b",
)
_REVERSIBLE_PATTERNS = (
    "\\b(reversible|undo|restore|recover|trash|corbeille|annuler|restaurer|récupérer)\\b",
)
_EXTERNAL_TRANSFER_PATTERNS = (
    "\\b(send|forward|transmit|relay|upload|post|share|mirror|copy|envoyer|transmettre|relayer|téléverser|partager|copi(?:er|e|es|ent|é|ée|és|ées))\\b.{0,80}\\b(external|remote|off-site|third-party|off-platform|outside|url|endpoint|webhook|collector|recipient|public|externe|distant|hors site|tiers|hors plateforme|collecteur|destinataire)\\b",
    "\\b(external|remote|off-site|third-party|off-platform|outside|url|endpoint|webhook|collector|recipient|public|externe|distant|hors site|tiers|hors plateforme|collecteur|destinataire)\\b.{0,80}\\b(send|forward|transmit|relay|upload|post|share|mirror|copy|envoyer|transmettre|relayer|téléverser|partager|copi(?:er|e|es|ent|é|ée|és|ées))\\b",
)
_PUBLIC_EXPOSURE_PATTERNS = (
    "\\b(make|publish|share|expose|rendre|publier|partager|exposer)\\b.{0,60}\\b(public(?:ly)?|accessible to anyone|anyone|anonymous(?:ly)?|anonymous visitors?|without authentication|public(?:que)?|tout le monde|anonyme|sans authentification)\\b",
)
_URL_RE = re.compile("https?://[^\\s)>\\]\\\"']+", re.IGNORECASE)
_SENSITIVE_DATA = {
    "credentials",
    "personal_data",
    "financial_data",
    "location",
    "sensitive_data",
}
_SENSITIVE_ACTIONS = {"delete", "execute", "authorize", "transact"}
_SENSITIVE_SIDE_EFFECTS = {
    "destructive",
    "external_transfer",
    "code_execution",
    "access_control_change",
    "financial_transaction",
    "public_exposure",
}
