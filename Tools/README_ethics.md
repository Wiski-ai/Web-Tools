# H8Suite — Rappel d'éthique et bonnes pratiques

Ce document explique les règles éthiques et légales à respecter lors de l'utilisation des outils fournis (JS Endpoint Extractor, Logic Bypass Toolkit).

Important — Légalité et éthique
- N'exécute ces outils que sur des cibles pour lesquelles tu disposes d'une autorisation explicite :
  - CTF / challenges conçus pour cela,
  - Environnements de test que tu possèdes ou auxquels tu as accès,
  - Clients/entreprises seulement si tu as un contrat ou une autorisation écrite.
- Toute utilisation sans autorisation peut être illégale et causer des dommages. L'auteur (H8Laws) décline toute responsabilité pour un usage inapproprié.

Bonnes pratiques
- Limite la portée (scope) de tes tests. Respecte les règles du challenge ou du contrat.
- Ne réalise jamais d'attaques destructrices ou intrusive sans permission (ex : masscan agressif, fuzzing intensif).
- Avant d'exécuter des tests automatisés sur une cible réelle :
  - Obtiens l'autorisation écrite du propriétaire.
  - Informe les parties concernées de la fenêtre de test si nécessaire.
  - Prévois un plan de rollback / contact pour stopper les tests en cas d'incident.

Responsible disclosure
- Si tu trouves une vulnérabilité sur une cible réelle (hors CTF), suis une procédure de responsible disclosure :
  - Identifie correctement la vulnérabilité et l'impact.
  - Contacte le propriétaire/mainteneur via les canaux officiels (bug bounty, support, sécurité).
  - Fournis un rapport clair, reproductible, et propose des mesures d'atténuation.
  - Laisse au responsable le temps de corriger avant toute divulgation publique.

Sécurité personnelle
- Ne partage pas les identifiants, tokens, ou données sensibles que tu obtiens.
- Utilise des environnements isolés (VM, containers) pour tes tests.
- Fais attention aux scripts tiers et valides leur contenu avant exécution.

Quelques recommandations pratiques
- Préfère des tests non-destructifs d'abord (baselines, lecture) puis intensifie seulement si autorisé.
- Conserve des logs et traces de tes actions (utile en cas d'anomalie).
- Pour tout doute légal, consulte un juriste ou demande l'autorisation formelle.

Contact / Auteurs
- Outils fournis par : H8Laws
- Ces outils sont fournis "as-is" pour apprentissage, CTF et environnements de test.
- Contact pro h8l4ws@gmail.com
