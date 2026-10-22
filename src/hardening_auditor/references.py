"""Reference frameworks cited by the rule catalogue."""

from __future__ import annotations

ANSSI_GUIDE = "ANSSI, Guide d'hygiène informatique (v2.0, 2017)"

# The 42 measures of the ANSSI hygiene guide, by number. Rules cite them as integers so the
# titles stay consistent across the catalogue.
ANSSI_MEASURES: dict[int, str] = {
    1: "Former les équipes opérationnelles à la sécurité des systèmes d'information",
    2: "Sensibiliser les utilisateurs aux bonnes pratiques élémentaires de sécurité informatique",
    3: "Maîtriser les risques de l'infogérance",
    4: "Identifier les informations et serveurs les plus sensibles et maintenir un schéma du réseau",
    5: "Disposer d'un inventaire exhaustif des comptes privilégiés et le maintenir à jour",
    6: "Organiser les procédures d'arrivée, de départ et de changement de fonction des utilisateurs",
    7: "Autoriser la connexion au réseau de l'entité aux seuls équipements maîtrisés",
    8: "Identifier nommément chaque personne accédant au système et distinguer les rôles utilisateur/administrateur",
    9: "Attribuer les bons droits sur les ressources sensibles du système d'information",
    10: "Définir et vérifier des règles de choix et de dimensionnement des mots de passe",
    11: "Protéger les mots de passe stockés sur les systèmes",
    12: "Changer les éléments d'authentification par défaut sur les équipements et services",
    13: "Privilégier lorsque c'est possible une authentification forte",
    14: "Mettre en place un niveau de sécurité minimal sur l'ensemble du parc informatique",
    15: "Se protéger des menaces relatives à l'utilisation de supports amovibles",
    16: "Utiliser un outil de gestion centralisée afin d'homogénéiser les politiques de sécurité",
    17: "Activer et configurer le pare-feu local des postes de travail",
    18: "Chiffrer les données sensibles transmises par voie Internet",
    19: "Segmenter le réseau et mettre en place un cloisonnement entre ces zones",
    20: "S'assurer de la sécurité des réseaux d'accès Wi-Fi et de la séparation des usages",
    21: "Utiliser des protocoles réseaux sécurisés dès qu'ils existent",
    22: "Mettre en place une passerelle d'accès sécurisé à Internet",
    23: "Cloisonner les services visibles depuis Internet du reste du système d'information",
    24: "Protéger sa messagerie professionnelle",
    25: "Sécuriser les interconnexions réseau dédiées avec les partenaires",
    26: "Contrôler et protéger l'accès aux salles serveurs et aux locaux techniques",
    27: "Interdire l'accès à Internet depuis les postes ou serveurs utilisés pour l'administration du SI",
    28: "Utiliser un réseau dédié et cloisonné pour l'administration du système d'information",
    29: "Limiter au strict besoin opérationnel les droits d'administration sur les postes de travail",
    30: "Prendre des mesures de sécurisation physique des terminaux nomades",
    31: "Chiffrer les données sensibles, en particulier sur le matériel potentiellement perdable",
    32: "Sécuriser la connexion réseau des postes utilisés en situation de nomadisme",
    33: "Adopter des politiques de sécurité dédiées aux terminaux mobiles",
    34: "Définir une politique de mise à jour des composants du système d'information",
    35: "Anticiper la fin de la maintenance des logiciels et systèmes et limiter les adhérences logicielles",
    36: "Activer et configurer les journaux des composants les plus importants",
    37: "Définir et appliquer une politique de sauvegarde des composants critiques",
    38: "Procéder à des contrôles et audits de sécurité réguliers puis appliquer les actions correctives",
    39: "Désigner un référent en sécurité des systèmes d'information et le faire connaître auprès du personnel",
    40: "Définir une procédure de gestion des incidents de sécurité",
    41: "Mener une analyse de risques formelle",
    42: "Privilégier l'usage de produits ou de services qualifiés par l'ANSSI",
}


def anssi_label(measure: int) -> str:
    return f"Mesure {measure} : {ANSSI_MEASURES[measure]}"
