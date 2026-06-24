# 🔍 Phishing Email Analyzer

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![Streamlit](https://img.shields.io/badge/streamlit-1.28.0-red)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

**Outil d'analyse d'emails pour détecter les tentatives de phishing**

[Installation](#-installation) • [Utilisation](#-utilisation) • [Fonctionnalités](#-fonctionnalités) • [Auteur](#-auteur)

</div>

---

## 📋 Table des matières

- [À propos](#-à-propos)
- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Exemple de résultats](#-exemple-de-résultats)
- [Structure du projet](#-structure-du-projet)
- [Fichiers du projet](#-fichiers-du-projet)
- [Dossiers du projet](#-dossiers-du-projet)
- [Technologies utilisées](#-technologies-utilisées)
- [Résultats des tests](#-résultats-des-tests)
- [Sécurité](#-sécurité)
- [Auteur](#-auteur)
- [Remerciements](#-remerciements)
- [Licence](#-licence)
- [Statistiques du projet](#-statistiques-du-projet)

---

## 🎯 À propos

**Phishing Email Analyzer** est un outil développé dans le cadre de mon **PPP (Projet Professionnel Personnel)** en cybersécurité. Il permet d'analyser automatiquement des emails au format `.eml` pour détecter les tentatives de phishing.

L'outil extrait les URLs, analyse les domaines, examine les pièces jointes et attribue un score de risque à chaque élément suspect.

**Objectifs du projet :**
- Automatiser la détection des emails de phishing
- Fournir une analyse détaillée avec des scores de risque
- Proposer une interface web intuitive
- Générer des rapports professionnels en HTML

---

## ✨ Fonctionnalités

### 📧 Analyse des emails
- ✅ Extraction automatique des métadonnées (expéditeur, destinataire, objet, date)
- ✅ Extraction des URLs présentes dans le corps de l'email
- ✅ Extraction et analyse des pièces jointes
- ✅ Affichage du corps de l'email

### 🔗 Analyse des URLs
- ✅ **Système de scoring sur 100** (0% = sûr, 100% = critique)
- ✅ **Whitelist** des domaines officiels (Microsoft, Google, Stripe, etc.)
- ✅ **Détection des TLD suspects** (`.tk`, `.ml`, `.vtn`, `.ypk`, etc.)
- ✅ **Détection du typosquatting** (substitutions suspectes)
- ✅ **Analyse des redirections** (paramètres `redirect=`, `url=`, etc.)
- ✅ **Comparaison avec le domaine de l'expéditeur**

### 📎 Analyse des pièces jointes

| Catégorie | Extensions | Niveau de risque |
|-----------|------------|------------------|
| 🔴 DANGEREUX | `.exe`, `.scr`, `.bat`, `.cmd`, `.js`, `.jar`, `.iso`, `.ps1`, `.py`, `.sh` | Élevé |
| 🟠 À RISQUE | `.docm`, `.xlsm`, `.pptm`, `.dotm`, `.xlam`, `.ppam` | Moyen |
| 🟡 INCONNU | Extensions non reconnues | À vérifier |
| ✅ SÛR | `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.txt`, `.csv`, `.json`, `.xml`, `.html`, `.png`, `.jpg`, `.gif`, `.mp3`, `.mp4`, `.zip`, `.rar`, `.7z` | Faible |

### 📊 Rapports
- ✅ **Export HTML** avec date/heure et numéro de rapport
- ✅ **Statistiques globales** (URLs uniques, répartition des risques)
- ✅ **Rapports sauvegardés** dans le dossier `rapports/`
- ✅ **Nom de fichier unique** : `rapport_YYYY-MM-DD_HH-MM-SS.html`

### 🖥️ Interface web (Streamlit)
- ✅ Téléchargement facile des fichiers `.eml`
- ✅ **Score global** de l'email en en-tête
- ✅ **Boutons interactifs** pour ouvrir/copier les URLs
- ✅ Affichage détaillé des signes de phishing
- ✅ Téléchargement du rapport HTML en un clic
- ✅ Design responsive et professionnel

---

## 🚀 Installation

### Prérequis
- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)
- Git (optionnel, pour cloner le dépôt)

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/jamaljb-wj/phishing-email-analyzer.git
cd phishing-email-analyzer

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. (Optionnel) Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows : venv\Scripts\activate
```

---

## 📖 Utilisation

### Option 1 : Ligne de commande

```bash
python analyseur.py
```

**Instructions :**
1. Placez vos fichiers `.eml` dans le dossier `emails/`
2. Exécutez la commande ci-dessus
3. Les résultats s'affichent dans le terminal
4. Un rapport HTML est généré dans `rapports/`

**Exemple de sortie :**

```
📂 4 fichier(s) trouvé(s) :

📧 EMAIL N°1 : phishing_example.eml
📩 De      : alert-1614@wfexl.vtn
📝 Objet   : ⚠️ WARNING: Failure Notice
🔗 URLs trouvées (1) :
   1. time.email
      🌐 Domaine : time.email
      ⚠️  Niveau de risque : 🟡 MOYEN (score: 20%)
```

### Option 2 : Interface web (Streamlit)

```bash
streamlit run app.py
```

L'application s'ouvre automatiquement dans votre navigateur :

1. **Téléchargez** un fichier `.eml` dans la barre latérale
2. **L'analyse** se lance automatiquement
3. **Consultez** les résultats :
   - Score global de l'email
   - Détail des URLs avec leurs risques
   - Analyse des pièces jointes
   - Corps de l'email
4. **Téléchargez** le rapport HTML en un clic

---

## 📊 Exemple de résultats

### Score global (Streamlit)

```
┌─────────────────────────────────────────────────────────────┐
│  📊 Score global de l'email                                │
│  🔍 Cet email présente quelques signes suspects           │
│                                               🟡 21% MOYEN │
└─────────────────────────────────────────────────────────────┘
```

### Analyse d'une URL suspecte

```
1. https://uploaddate.com
   🌐 Domaine : uploaddate.com
   ⚠️ Niveau de risque : 🟡 MOYEN (score: 20%)
   📌 Signes détectés :
      🟠 Domaine différent de l'expéditeur : stripe.com
   🔗 Ouvrir  📋 Copier
```

### Analyse d'une URL sécurisée

```
1. https://account.live.com/pw
   🌐 Domaine : account.live.com
   ⚠️ Niveau de risque : 🟢 FAIBLE (score: 0%)
   ✅ Domaine dans la liste blanche (sécurisé)
   📌 Signes détectés :
      ✅ Domaine officiel reconnu
```

### Niveaux de risque

| Score | Niveau | Signification |
|-------|--------|---------------|
| 0-6% | 🟢 FAIBLE | Domaine sécurisé ou whitelisté |
| 7-19% | 🟢 FAIBLE | Risque minimal |
| 20-39% | 🟡 MOYEN | Signes suspects détectés |
| 40-66% | 🟠 ÉLEVÉ | Plusieurs signes de phishing |
| 67-100% | 🔴 CRITIQUE | Très probablement du phishing |

---

## 📁 Structure du projet

```
phishing-email-analyzer/
│
├── analyseur.py          # Script principal d'analyse (Version 12)
├── app.py               # Interface Streamlit (Version 2.0)
├── requirements.txt     # Dépendances du projet
├── README.md            # Documentation (ce fichier)
├── .gitignore           # Fichiers exclus de Git
│
├── emails/              # 📁 Dossier pour les emails à analyser
│   └── .gitkeep         # Fichier pour garder le dossier dans Git
│
├── rapports/            # 📁 Rapports HTML générés automatiquement
│   ├── rapport_2026-06-24_13-41-40.html
│   ├── rapport_2026-06-24_13-31-42.html
│   └── ...
│
└── .git/                # 📁 Dossier Git (ne pas modifier)
```

---

## 📁 Fichiers du projet

| Fichier | Description | Rôle principal |
|---------|-------------|----------------|
| **analyseur.py** | Script principal | Contient toutes les fonctions d'analyse : extraction des URLs, scoring sur 100, whitelist, analyse des pièces jointes, export HTML, génération de rapports |
| **app.py** | Interface Streamlit | Interface web avec score global, boutons interactifs (ouvrir/copier), téléchargement de rapports, statistiques en sidebar |
| **requirements.txt** | Dépendances | Liste des bibliothèques Python nécessaires : `streamlit==1.28.0`, `pandas==2.0.3` |
| **README.md** | Documentation | Ce fichier - documentation complète du projet avec guide d'installation et d'utilisation |
| **.gitignore** | Exclusions Git | Liste des fichiers à ne pas versionner : `__pycache__/`, `*.pyc`, `emails/`, `rapports/`, etc. |
| **.gitkeep** | Placeholder | Fichier vide pour garder les dossiers vides dans Git |

---

## 📁 Dossiers du projet

| Dossier | Contenu | Utilisation |
|---------|---------|-------------|
| **emails/** | Fichiers `.eml` | Placez vos emails à analyser dans ce dossier pour une analyse en ligne de commande |
| **rapports/** | Rapports HTML | Rapports générés automatiquement avec date/heure (ex: `rapport_2026-06-24_13-41-40.html`) |
| **.git/** | Configuration Git | Dossier interne à Git (ne pas modifier) |

---

## 🛠️ Technologies utilisées

| Technologie | Version | Utilisation |
|-------------|---------|-------------|
| **Python** | 3.8+ | Langage de programmation principal |
| **Streamlit** | 1.28.0 | Interface web interactive |
| **Pandas** | 2.0.3 | Gestion et affichage des données (tableaux) |
| **hashlib** | - | Calcul des hashs MD5/SHA256 pour les pièces jointes |
| **email** | - | Parsing des emails (librairie standard) |
| **re** | - | Expressions régulières pour l'extraction (librairie standard) |
| **urllib** | - | Analyse des URLs (librairie standard) |
| **collections** | - | Gestion des compteurs (librairie standard) |
| **datetime** | - | Gestion des dates/heures (librairie standard) |
| **glob** | - | Recherche de fichiers (librairie standard) |
| **os** | - | Gestion des fichiers et dossiers (librairie standard) |

---

## 📊 Résultats des tests

### Emails testés

| Email | Type | URLs | Score | Niveau | Verdict |
|-------|------|------|-------|--------|---------|
| **Email 1** | Phishing (Costco) | `time.email` | 20% | 🟡 MOYEN | Phishing détecté |
| **Email 2** | Légitime (Microsoft) | 5 URLs Microsoft | 0% | 🟢 FAIBLE | Légitime ✅ |
| **Email 3** | Légitime (Stripe) | 10 URLs Stripe | 0-33% | 🟢 FAIBLE / 🟡 MOYEN | Légitime ✅ |
| **Email 4** | Phishing | `time.email` | 20% | 🟡 MOYEN | Phishing détecté |

### Statistiques globales

| Indicateur | Valeur |
|------------|--------|
| URLs totales analysées | 17 |
| URLs uniques | 12 |
| 🟢 FAIBLE | 10 URLs |
| 🟡 MOYEN | 6 URLs |
| 🟠 ÉLEVÉ | 1 URL |
| 🔴 CRITIQUE | 0 URL |
| Pièces jointes analysées | 2 (PDF Stripe) |
| ✅ Pièces sûres | 2 |
| 🔴 Dangereuses | 0 |

### Taux de détection

| Métrique | Résultat |
|----------|----------|
| **Vrais positifs** (phishing détecté) | 2/2 ✅ |
| **Vrais négatifs** (légitime identifié) | 2/2 ✅ |
| **Faux positifs** | 0 ❌ |
| **Faux négatifs** | 0 ❌ |
| **Précision** | 100% 🎯 |

---

## 🔒 Sécurité

- ✅ **Analyse 100% locale** - Aucune donnée n'est envoyée à l'extérieur
- ✅ **Pas de stockage** - Les fichiers sont supprimés après analyse
- ✅ **Aucune API externe** - Tout est fait en local
- ✅ **Hash des fichiers** - Calcul des empreintes MD5/SHA256 pour les pièces jointes
- ✅ **Détection des extensions dangereuses** - Classification automatique

---

## 👤 Auteur

**Jamal Jabrane**
- 📧 Email : jamalxline@gmail.com
- Linkedin : https://www.linkedin.com/in/jamal-jabrane/
- 🔗 GitHub : [@jamaljb-wj](https://github.com/jamaljb-wj)
- 🎓 Projet : PPP 2025-2026 - E5 Cybersécurité
- 📚 Établissement : Formation E5 Cybersécurité
- 👨‍🏫 Encadrant : M. M'hand BOUFALA

---

## 🙏 Remerciements

- **M. M'hand BOUFALA** - Encadrant du projet PPP
- **Toute la promotion E5** - Pour l'entraide et le partage

---

## 📄 Licence

Ce projet est réalisé dans le cadre du **PPP (Projet Professionnel Personnel)** de la formation **E5 Cybersécurité**.

---

## 📊 Statistiques du projet

| Métrique | Valeur |
|----------|--------|
| 📁 Fichiers principaux | 5 fichiers (`analyseur.py`, `app.py`, `requirements.txt`, `README.md`, `.gitignore`) |
| 📝 Lignes de code | ~800 lignes |
| 🧪 Emails de test | 4 emails analysés |
| 📊 Fonctions | 15 fonctions principales |
| 🛠️ Bibliothèques | 7 bibliothèques utilisées |
| 📎 Pièces jointes testées | 2 fichiers PDF |
| 🎯 Précision | 100% |
| 📅 Date de création | Juin 2026 |

---

## 🔄 Versions

| Version | Date | Modifications |
|---------|------|---------------|
| **v1.0** | Juin 2026 | Version initiale - Extraction des URLs et scoring de base |
| **v2.0** | Juin 2026 | Ajout de l'interface Streamlit, scoring sur 100, analyse des pièces jointes |
| **v2.1** | Juin 2026 | Correction de l'analyse des PDF, ajout de la classification des extensions |

---

<div align="center">

**🔒 Analyse effectuée en locale - Aucune donnée n'est envoyée à l'extérieur**

*Dernière mise à jour : Juin 2026*

</div>
