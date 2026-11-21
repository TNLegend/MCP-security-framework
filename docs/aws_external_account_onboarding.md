# Connecter un compte AWS indépendant au framework

Cette procédure concerne **Cloud Security / Deploy Security**, pas l'enregistrement de serveurs MCP. Elle s'applique à une installation administrée du framework, avec un ou plusieurs comptes AWS autorisant explicitement les contrôles. **Aucun compte AWS personnel n'est codé en dur.**

## Architecture de confiance

L'application utilise **boto3/STS**. L'administrateur choisit une source d'identité déjà disponible **sur l'hôte du backend** :

- **SDK identity** : rôle IAM associé à EC2/ECS/EKS/Lambda ou identifiants temporaires fournis à l'environnement du backend. Aucune commande AWS CLI n'est exigée.
- **Existing local AWS profile** : référence à un profil AWS configuré sur cet hôte. L'AWS CLI peut aider à créer ou renouveler le profil, mais demeure facultative. Le navigateur de l'administrateur n'est pas automatiquement une session boto3 sur le serveur.

Si le compte cible est différent de celui de l'identité source, son administrateur AWS crée un **rôle d'audit à permissions limitées**, avec une politique de confiance autorisant `sts:AssumeRole` depuis le principal du framework. Le rôle du serveur MCP exécutant des actions cloud **ne doit pas** être utilisé comme rôle de scanner.

Exemple de **politique de confiance sur le rôle du compte cible** (remplacer tous les placeholders avant validation par un administrateur AWS) :

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:role/FRAMEWORK_AUDIT_PRINCIPAL"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "GENERATED_UNIQUE_EXTERNAL_ID"
      }
    }
  }]
}
```

Le rôle source doit également être autorisé à appeler `sts:AssumeRole` sur ce rôle cible ; la relation de confiance ne suffit pas à elle seule. L'*External ID* est une condition de confiance et non un mot de passe : le framework ne peut pas accéder à un compte AWS sans autorisation IAM explicite. Un External ID distinct et aléatoire est conseillé par compte intégré, en particulier si plusieurs organisations partagent le même principal d'audit.

## Depuis le GUI

1. Ouvrir **Cloud security → AWS connections → Add AWS environment** en tant qu'ADMIN.
2. Indiquer un nom d'environnement, 1 à 3 régions et les services EC2/S3/IAM.
3. Choisir **SDK identity** ou **Existing local AWS profile**. Il s'agit de la source d'identité **du backend**, et non du compte cible.
4. Renseigner **Expected AWS account ID** (12 chiffres), l'ARN du rôle d'audit du compte cible et, si ce rôle est inter-comptes, son *External ID*. Le GUI peut générer un identifiant unique et affiche une **politique de confiance indicative** avec le rôle source à compléter.
5. Faire configurer et approuver ce rôle et ses permissions par l'administrateur du compte cible, puis cliquer sur **Test connection**. La réponse `CONNECTED` suppose un appel STS réel et l'identité du compte attendu. Elle ne confirme **pas** l'accès à toutes les ressources.
6. Dans **Advanced AWS checks**, cliquer sur **Check read-only AWS permissions**, puis lancer **Start advanced read-only audit** avec Prowler 5.51.0 si le moteur est installé. Les permissions manquantes restent DENIED/UNKNOWN ; aucune politique n'est automatiquement élargie.

Le framework n'enregistre pas de clé AWS permanente. La configuration ne contient que le nom du profil, l'ARN du rôle, l'External ID (non secret), le compte attendu et la portée de l'audit ; les jetons STS sont uniquement en mémoire. Une modification des paramètres d'identité ou du compte attendu invalide le statut `CONNECTED` et impose un nouveau test. Les audits historiques sont conservés.

## Sécurité et limitations

- La liste des environnements est partagée entre les utilisateurs autorisés **d'une même installation** ; le code actuel ne fournit **pas** une isolation forte entre organisations locataires. Ne pas présenter cette installation comme un SaaS multi-tenant sécurisé.
- La création du rôle IAM et l'approbation de sa politique de confiance ont lieu **dans le compte AWS cible**. Le GUI ne doit pas accepter de mot de passe AWS, de clés secrètes, ni demander des privilèges administrateur cloud.
- Le backend prend en charge l'option `ExternalId` avec `AssumeRole`, mais les anciens environnements sans External ID continuent de fonctionner sans modification automatique de leur IAM.
- L'hôte du backend doit posséder une source d'identité autorisée. Un profil AWS nommé sur le PC personnel de l'utilisateur ne devient pas automatiquement accessible dans un conteneur ou sur un serveur distant.
- Prowler est un **scanner**, pas un fournisseur d'authentification. Le backend transmet à son processus isolé une session STS temporaire. AWS CLI ne fait partie ni des prérequis de Prowler ni du démarrage générique.
- L'interface ne possède pas encore de flux navigateur « Sign in with AWS » universel, ni de procédure de configuration du rôle AWS complètement automatique. Les comptes externes réels nécessitent leurs propres approbations et un test de confiance inter-comptes.
- Un audit Prowler achevé peut contenir des findings et des vérifications UNKNOWN. `COMPLETED` signifie « exécution du scanner terminée », pas « compte sécurisé ».

## Preuves de validation en qualification

Les contrôles suivants n'ont pas modifié l'environnement principal :

- API synthétique : validation de l'External ID, du compte attendu, de l'appel STS avec `ExternalId`, du refus d'une identité inattendue, de l'édition et de la conservation de la configuration.
- PostgreSQL jetable : migration incrémentale idempotente, anciens environnements préservés et nouveaux paramètres restitués par l'ORM.
- Chromium : création d'un compte AWS **fictif** distinct via le GUI en ADMIN, refus des actions ADMIN pour VIEWER et impossibilité de démarrer son audit avant `Test connection`.
- Compte AWS de démonstration existant : STS, EC2, IAM et Prowler réels en lecture seule. Cela **ne prouve pas** une délégation à un deuxième compte AWS réel.

Les campagnes de régression doivent rester vertes avant de promouvoir la branche candidate en production.
