# 🔐 Application de Chiffrement RSA et d'Authentification

## 📌 Présentation du projet

Ce projet consiste à développer une application en Python permettant de proposer un système d'authentification des utilisateurs et des fonctionnalités liées au chiffrement RSA et à la gestion des certificats numériques.

L'application dispose d'une interface en ligne de commande interactive qui permet aux utilisateurs de s'enregistrer, de se connecter et de quitter l'application.

L'objectif est de mettre en pratique des concepts fondamentaux de la cybersécurité, notamment la cryptographie asymétrique, l'authentification et la protection des données.

## 🎯 Objectifs

- Comprendre le fonctionnement de la cryptographie asymétrique RSA.
- Mettre en place un menu interactif en Python.
- Organiser le code en plusieurs modules.
- Proposer des fonctionnalités d'enregistrement et d'authentification.
- Étudier l'utilisation des certificats numériques pour vérifier l'identité.
- Se familiariser avec les bibliothèques Python et les bonnes pratiques de développement sécurisé.

## 🛠️ Technologies utilisées

- **Python 3** — langage de programmation.
- **Colorama** — affichage de texte coloré dans le terminal.
- **Art** — génération de texte ASCII décoratif.
- **Cowsay** — affichage de messages illustrés dans le terminal.
- **RSA** — algorithme de cryptographie asymétrique, au cœur du projet.

## 📂 Structure du projet

```text
RSA-Encryption-Application/
│
├── main.py                # Point d'entrée de l'application
├── enregistrement.py      # Module d'enregistrement des utilisateurs
├── Authentification.py    # Module d'authentification
├── README.md              # Documentation du projet
└── requirements.txt       # Dépendances Python
```

*Remarque : cette structure est indicative et peut être adaptée à l'organisation réelle de tes fichiers.*

## ⚙️ Fonctionnalités

### 1. Enregistrement des utilisateurs

L'utilisateur sélectionne l'option `1` pour accéder au module d'enregistrement.

### 2. Authentification

L'utilisateur sélectionne l'option `2` pour accéder à la fonction de connexion.

### 3. Quitter l'application

L'utilisateur sélectionne l'option `3` pour fermer l'application.

### 4. Interface interactive

L'application affiche un menu textuel, un titre décoratif et un message d'accueil dans le terminal.

## 🚀 Installation

### Prérequis

- Python 3.10 ou version ultérieure, pour la syntaxe `match/case`.
- Git.
- pip.

### Étape 1 : Cloner le dépôt

```bash
git clone https://github.com/VOTRE-NOM/RSA-Encryption-Application.git
```

Remplace `VOTRE-NOM` par ton nom d'utilisateur GitHub et adapte l'URL au nom réel de ton dépôt.

### Étape 2 : Accéder au projet

```bash
cd RSA-Encryption-Application
```

### Étape 3 : Installer les dépendances

```bash
pip install colorama art cowsay
```

### Étape 4 : Lancer l'application

```bash
python main.py
```

## 💻 Exemple d'utilisation

```text
 _______ _   _   ____
| Welcome TN      |

 ______________________________
< app chiffrement and Certificat RSA >
 ------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

1: Enregistre vous
2: Login
3: Quiter app

tapper votre choix :
```

L'affichage exact dépend des bibliothèques utilisées et de la mise en forme du terminal.

## 🔒 Sécurité

Le projet aborde les principes de la cryptographie et de l'authentification. Pour une utilisation sécurisée, plusieurs points doivent être pris en compte :

- Utiliser une bibliothèque cryptographique reconnue pour générer les clés RSA et réaliser les opérations cryptographiques.
- Ne jamais stocker les mots de passe en clair ; utiliser un mécanisme de hachage adapté, tel qu'Argon2id.
- Protéger les clés privées contre tout accès non autorisé.
- Vérifier la validité et la chaîne de confiance des certificats numériques.
- Utiliser une taille de clé RSA adaptée aux exigences de sécurité actuelles.
- Préférer RSA-OAEP pour le chiffrement et RSA-PSS pour les signatures numériques.

**Important :** le code principal présenté constitue une interface de menu. Les fonctionnalités réelles de chiffrement RSA et de gestion des certificats dépendent de l'implémentation des modules associés.

## 📚 Compétences développées

- Programmation Python.
- Cryptographie asymétrique.
- Notions de gestion des certificats numériques.
- Authentification des utilisateurs.
- Organisation modulaire d'une application.
- Sensibilisation aux bonnes pratiques de cybersécurité.

## 🔮 Améliorations possibles

- Génération et gestion des paires de clés RSA.
- Chiffrement et déchiffrement de messages.
- Signature numérique et vérification des signatures.
- Création et validation de certificats numériques.
- Gestion sécurisée des utilisateurs.
- Ajout de tests unitaires et de journaux d'événements.

## 👨‍💻 Auteur

**Mohamed Taha Malaiki**

Projet personnel de développement Python et de mise en pratique des concepts de cybersécurité.

## 📄 Licence

Ce projet peut être distribué sous licence MIT après ajout d'un fichier `LICENSE` correspondant et vérification des conditions de distribution des dépendances.
