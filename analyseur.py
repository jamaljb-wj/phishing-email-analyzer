# analyseur.py
# Version 12 : Système de scoring avancé avec score sur 100 + export HTML + analyse des pièces jointes (corrigée)

from email import policy
from email.parser import BytesParser
import os
import glob
import re
from urllib.parse import urlparse, parse_qs
import html
from collections import Counter
import datetime
import hashlib

# ============================================================
# LISTES DE CONFIANCE (WHITELIST)
# ============================================================

# Domaines officiels considérés comme SÉCURISÉS
DOMAINES_WHITELIST = [
    # Microsoft
    'microsoft.com',
    'live.com',
    'outlook.com',
    'office.com',
    'azure.com',
    'windows.com',
    'msn.com',
    'accountprotection.microsoft.com',
    'login.microsoftonline.com',
    'go.microsoft.com',
    'aka.ms',
    
    # Google
    'google.com',
    'gmail.com',
    'youtube.com',
    'drive.google.com',
    'accounts.google.com',
    'mail.google.com',
    
    # Apple
    'apple.com',
    'icloud.com',
    'me.com',
    'mac.com',
    
    # Autres services connus
    'amazon.com',
    'paypal.com',
    'bank.com',
    'costco.com',
    'github.com',
    'linkedin.com',
    'twitter.com',
    'facebook.com',
    'instagram.com',
    'whatsapp.com',
    'telegram.org',
    'dropbox.com',
    'box.com',
    'slack.com',
    'zoom.us',
    'teams.microsoft.com',
    'msteams.com',
    
    # Services français
    'orange.fr',
    'sfr.fr',
    'free.fr',
    'bouyguestelecom.fr',
    'laposte.net',
    'yahoo.fr',
    'hotmail.fr',
    'live.fr',
    'outlook.fr',
    
    # Services de paiement
    'stripe.com',
    'pay.stripe.com',
    'dashboard.stripe.com',
    'billing.stripe.com',
]

# Domaines de tracking légitimes
TRACKING_LEGITIME = [
    'click.e.email.microsoft.com',
    'click.email.microsoft.com',
    'links.e.microsoft.com',
    'trk.e.email.microsoft.com',
    'track.e.microsoft.com',
]

# TLD suspects
TLD_SUSPECTS = [
    '.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.online',
    '.site', '.website', '.space', '.tech', '.store', '.shop',
    '.vtn', '.ypk', '.tjv', '.gq', '.bid', '.date', '.download',
    '.review', '.trade', '.webcam', '.work', '.party', '.science',
    '.faith', '.click', '.link', '.info', '.biz', '.cc', '.co'
]

# ============================================================
# EXTENSIONS DE FICHIERS - CLASSIFICATION
# ============================================================

# Extensions DANGEREUSES (exécutables, scripts, etc.)
EXTENSIONS_DANGEREUSES = {
    '.exe': 'Exécutable Windows',
    '.scr': 'Écran de veille (peut être malveillant)',
    '.bat': 'Fichier batch',
    '.cmd': 'Fichier commande',
    '.com': 'Fichier commande',
    '.pif': 'Fichier d\'informations',
    '.vbs': 'Script VBScript',
    '.js': 'Script JavaScript',
    '.jar': 'Fichier Java',
    '.iso': 'Image disque',
    '.img': 'Image disque',
    '.msi': 'Installeur Windows',
    '.ps1': 'Script PowerShell',
    '.py': 'Script Python',
    '.rb': 'Script Ruby',
    '.sh': 'Script Shell',
    '.wsf': 'Script Windows',
}

# Extensions À RISQUE (peuvent contenir des macros ou exploits)
EXTENSIONS_RISQUEES = {
    '.docm': 'Document Word avec macros',
    '.xlsm': 'Tableur Excel avec macros',
    '.pptm': 'Présentation avec macros',
    '.dotm': 'Modèle Word avec macros',
    '.xlam': 'Add-in Excel avec macros',
    '.ppam': 'Add-in PowerPoint avec macros',
    '.xltm': 'Modèle Excel avec macros',
    '.potm': 'Modèle PowerPoint avec macros',
}

# Extensions SÛRES (légitimes)
EXTENSIONS_SURES = {
    '.pdf': 'PDF',
    '.doc': 'Document Word',
    '.docx': 'Document Word (moderne)',
    '.xls': 'Tableur Excel',
    '.xlsx': 'Tableur Excel (moderne)',
    '.ppt': 'Présentation PowerPoint',
    '.pptx': 'Présentation PowerPoint (moderne)',
    '.txt': 'Fichier texte',
    '.csv': 'Fichier CSV',
    '.json': 'Fichier JSON',
    '.xml': 'Fichier XML',
    '.html': 'Page HTML',
    '.htm': 'Page HTML',
    '.png': 'Image PNG',
    '.jpg': 'Image JPEG',
    '.jpeg': 'Image JPEG',
    '.gif': 'Image GIF',
    '.bmp': 'Image BMP',
    '.svg': 'Image SVG',
    '.mp3': 'Fichier audio',
    '.mp4': 'Fichier vidéo',
    '.avi': 'Fichier vidéo',
    '.mov': 'Fichier vidéo',
    '.wav': 'Fichier audio',
    '.zip': 'Archive ZIP',
    '.rar': 'Archive RAR',
    '.7z': 'Archive 7z',
    '.tar': 'Archive TAR',
    '.gz': 'Archive GZ',
    '.bz2': 'Archive BZ2',
}

# ============================================================
# FONCTIONS DE VÉRIFICATION
# ============================================================

def est_domaine_whitelist(domaine):
    """Vérifie si un domaine est dans la liste blanche."""
    if not domaine:
        return False
    
    domaine = domaine.lower()
    
    if domaine in DOMAINES_WHITELIST:
        return True
    
    for whitelist in DOMAINES_WHITELIST:
        if domaine.endswith('.' + whitelist) or domaine == whitelist:
            return True
    
    return False

def est_domaine_tracking_legitime(domaine):
    """Vérifie si un domaine de tracking est légitime."""
    if not domaine:
        return False
    
    domaine = domaine.lower()
    
    for tracking in TRACKING_LEGITIME:
        if tracking in domaine or domaine.endswith('.' + tracking):
            return True
    
    return False

# ============================================================
# FONCTIONS D'EXTRACTION
# ============================================================

def extraire_urls(texte):
    """Extrait toutes les URLs d'un texte."""
    if not texte:
        return []
    
    pattern = r'https?://[^\s<>"\'\)]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'\)]*)?'
    
    urls = re.findall(pattern, texte, re.IGNORECASE)
    
    urls_propres = []
    for url in urls:
        url = re.sub(r'[.,;:!?)]+$', '', url)
        url = url.strip('"\'<>')
        if url and (url.startswith('http') or '.' in url):
            urls_propres.append(url)
    
    return urls_propres

def extraire_urls_parametres(url):
    """Extrait les URLs cachées dans les paramètres."""
    urls_trouvees = []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param, valeurs in params.items():
            for valeur in valeurs:
                if 'http' in valeur or 'https' in valeur:
                    urls_cachees = re.findall(r'https?://[^\s&]+', valeur)
                    urls_trouvees.extend(urls_cachees)
    except:
        pass
    
    return urls_trouvees

def extraire_domaine_expediteur(email_from):
    """Extrait le domaine de l'adresse email de l'expéditeur."""
    if not email_from:
        return ""
    
    match = re.search(r'<([^>]+)>', email_from)
    if match:
        email = match.group(1)
    else:
        email = email_from
    
    match = re.search(r'@([^\s]+)', email)
    if match:
        return match.group(1)
    
    return ""

# ============================================================
# ANALYSE DES PIÈCES JOINTES
# ============================================================

def analyser_piece_jointe(nom_fichier, contenu, taille):
    """
    Analyse une pièce jointe et détecte les signes de malveillance.
    Version améliorée avec classification des extensions.
    """
    resultat = {
        "nom": nom_fichier,
        "taille": taille,
        "extension": os.path.splitext(nom_fichier)[1].lower(),
        "hash_md5": "",
        "hash_sha256": "",
        "est_suspect": False,
        "est_dangereux": False,
        "est_risque": False,
        "signes": [],
        "classification": "✅ SÛR"
    }
    
    # Calcul des hashs
    try:
        resultat["hash_md5"] = hashlib.md5(contenu).hexdigest()
        resultat["hash_sha256"] = hashlib.sha256(contenu).hexdigest()
    except:
        pass
    
    extension = resultat["extension"]
    
    # 1. Vérifier si l'extension est DANGEREUSE
    if extension in EXTENSIONS_DANGEREUSES:
        resultat["est_suspect"] = True
        resultat["est_dangereux"] = True
        resultat["classification"] = "🔴 DANGEREUX"
        resultat["signes"].append(f"🔴 Extension exécutable : {EXTENSIONS_DANGEREUSES[extension]}")
    
    # 2. Vérifier si l'extension est À RISQUE
    elif extension in EXTENSIONS_RISQUEES:
        resultat["est_suspect"] = True
        resultat["est_risque"] = True
        resultat["classification"] = "🟠 À RISQUE"
        resultat["signes"].append(f"🟠 Extension avec macros : {EXTENSIONS_RISQUEES[extension]}")
    
    # 3. Vérifier si l'extension est SÛRE
    elif extension in EXTENSIONS_SURES:
        resultat["classification"] = "✅ SÛR"
        # Ne pas ajouter de signe, c'est un fichier légitime
    
    # 4. Extension inconnue
    else:
        resultat["est_suspect"] = True
        resultat["classification"] = "🟡 INCONNU"
        resultat["signes"].append(f"🟡 Extension non reconnue : {extension}")
    
    # 5. Vérifier la taille (moins de 1KB = suspect SAUF pour les fichiers texte)
    if taille < 1024 and taille > 0 and extension not in ['.txt', '.csv', '.json', '.xml', '.html', '.htm']:
        resultat["signes"].append("🟡 Fichier anormalement petit (< 1KB)")
        if not resultat["est_dangereux"] and not resultat["est_risque"]:
            resultat["est_suspect"] = True
    
    # 6. Vérifier la taille (plus de 10MB = suspect)
    if taille > 10 * 1024 * 1024:
        resultat["signes"].append("🟡 Fichier anormalement gros (> 10MB)")
    
    # 7. Détecter les doubles extensions (ex: document.pdf.exe)
    nom_sans_ext = os.path.splitext(nom_fichier)[0]
    if '.' in nom_sans_ext:
        resultat["est_suspect"] = True
        resultat["est_dangereux"] = True
        resultat["classification"] = "🔴 DANGEREUX"
        resultat["signes"].append("🔴 Double extension détectée (tentative d'usurpation)")
    
    # 8. Vérifier si le fichier est vide
    if taille == 0:
        resultat["signes"].append("🟡 Fichier vide")
    
    return resultat

def extraire_pieces_jointes(message):
    """
    Extrait les pièces jointes d'un email.
    Retourne une liste de dictionnaires contenant les informations des pièces jointes.
    """
    pieces = []
    try:
        if message.is_multipart():
            for part in message.walk():
                # Vérifier si c'est une pièce jointe
                content_disposition = part.get_content_disposition()
                if content_disposition and content_disposition.lower() == 'attachment':
                    nom_fichier = part.get_filename()
                    if nom_fichier:
                        try:
                            contenu = part.get_content()
                            taille = len(contenu) if contenu else 0
                            pieces.append({
                                "nom": nom_fichier,
                                "taille": taille,
                                "type": part.get_content_type(),
                                "contenu": contenu
                            })
                        except Exception as e:
                            pieces.append({
                                "nom": nom_fichier,
                                "taille": 0,
                                "type": part.get_content_type(),
                                "erreur": str(e)
                            })
    except Exception as e:
        pass
    
    return pieces

# ============================================================
# ANALYSE AVANCÉE DES URLS (SCORING SUR 100)
# ============================================================

def analyser_url(url, email_from="", email_domain=""):
    """
    Analyse une URL avec système de scoring avancé.
    Score final sur 100 (0% = sûr, 100% = critique).
    """
    resultat = {
        "url": url,
        "domaine": "",
        "signes_phishing": [],
        "niveau_risque": "🟢 FAIBLE",
        "parametres_redirection": [],
        "score": 0,          # Score sur 100
        "score_brut": 0,     # Score brut /15 (pour référence)
        "est_whitelist": False,
        "est_tracking": False
    }
    
    try:
        parsed = urlparse(url)
        domaine = parsed.netloc or parsed.path
        
        # Nettoyer le domaine
        domaine_propre = domaine
        if domaine_propre.startswith('www.'):
            domaine_propre = domaine_propre[4:]
        
        resultat["domaine"] = domaine_propre
        
        # ============================================================
        # 1. VÉRIFICATION WHITELIST (score = 0%)
        # ============================================================
        if est_domaine_whitelist(domaine_propre):
            resultat["est_whitelist"] = True
            resultat["niveau_risque"] = "🟢 FAIBLE"
            resultat["score"] = 0
            resultat["score_brut"] = 0
            resultat["signes_phishing"].append("✅ Domaine officiel reconnu")
            return resultat
        
        # ============================================================
        # 2. VÉRIFICATION TRACKING LÉGITIME (score = 0%)
        # ============================================================
        if est_domaine_tracking_legitime(domaine_propre):
            resultat["est_tracking"] = True
            resultat["niveau_risque"] = "🟢 FAIBLE"
            resultat["score"] = 0
            resultat["score_brut"] = 0
            resultat["signes_phishing"].append("✅ Domaine de tracking légitime")
            return resultat
        
        # ============================================================
        # 3. ANALYSE COMPLÈTE (hors whitelist)
        # ============================================================
        score_brut = 0
        resultat["signes_phishing"] = []
        
        # --- 3.1 Protocole HTTP (max +2) ---
        if parsed.scheme == "http":
            resultat["signes_phishing"].append("🔴 Utilise HTTP (non sécurisé)")
            score_brut += 2
        
        # --- 3.2 TLD suspects (max +3) ---
        for tld in TLD_SUSPECTS:
            if domaine_propre.endswith(tld):
                resultat["signes_phishing"].append(f"🔴 TLD suspect : {tld}")
                score_brut += 3
                break
        
        # --- 3.3 Substitutions (typosquatting) (max +2) ---
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
            '7': 't', '@': 'a', '!': 'i'
        }
        for chiffre, lettre in substitutions.items():
            if chiffre in domaine_propre:
                score_brut += 2
                resultat["signes_phishing"].append(f"🟠 Substitution suspecte : '{chiffre}' → '{lettre}'")
                break
        
        # --- 3.4 Longueur du domaine (max +2) ---
        if len(domaine_propre) > 40:
            score_brut += 2
            resultat["signes_phishing"].append("🟡 Domaine très long (suspect)")
        elif len(domaine_propre) > 30:
            score_brut += 1
            resultat["signes_phishing"].append("🟡 Domaine long")
        
        # --- 3.5 Sous-domaines multiples (max +2) ---
        parties = domaine_propre.split('.')
        if len(parties) > 5:
            score_brut += 2
            resultat["signes_phishing"].append(f"🟡 {len(parties)} sous-domaines (suspect)")
        elif len(parties) > 4:
            score_brut += 1
            resultat["signes_phishing"].append(f"🟡 {len(parties)} sous-domaines")
        
        # --- 3.6 Différence avec l'expéditeur (max +3) ---
        if email_domain and domaine_propre != email_domain:
            if not (domaine_propre.endswith('.' + email_domain) or 
                   email_domain.endswith('.' + domaine_propre)):
                score_brut += 3
                resultat["signes_phishing"].append(f"🟠 Domaine différent de l'expéditeur : {email_domain}")
        
        # --- 3.7 Mots sensibles (max +2) ---
        mots_sensibles = ['paypal', 'bank', 'secure', 'login', 'update', 
                          'verify', 'security', 'confirm', 'account', 
                          'microsoft', 'apple', 'amazon']
        
        for mot in mots_sensibles:
            if mot in domaine_propre.lower():
                if not any(domaine_propre.lower().endswith(ext) for ext in 
                          ['.com', '.fr', '.org', '.net', '.gov', '.edu']):
                    score_brut += 2
                    resultat["signes_phishing"].append(f"🔴 Contient '{mot}' mais n'est pas un domaine officiel")
                    break
        
        # --- 3.8 Redirections (max +3) ---
        if re.search(r'redirect|url=|goto|link=', url, re.IGNORECASE):
            score_brut += 2
            resultat["signes_phishing"].append("🟠 Paramètre de redirection détecté")
            
            urls_cachees = extraire_urls_parametres(url)
            if urls_cachees:
                score_brut += 1
                resultat["parametres_redirection"] = urls_cachees
                resultat["signes_phishing"].append(f"🟠 Redirige vers : {urls_cachees[0][:50]}...")
        
        # --- 3.9 Caractères spéciaux (max +1) ---
        if re.search(r'[^a-zA-Z0-9.\-]', domaine_propre):
            score_brut += 1
            resultat["signes_phishing"].append("🟡 Caractères spéciaux dans le domaine")
        
        # --- 3.10 Domaine non reconnu (bonus) ---
        if score_brut == 0:
            score_brut += 1
            resultat["signes_phishing"].append("🟡 Domaine non reconnu (vérification manuelle recommandée)")
        
        # --- Limiter le score brut à 15 ---
        score_brut = min(score_brut, 15)
        resultat["score_brut"] = score_brut
        
        # ============================================================
        # 4. CONVERSION EN SCORE SUR 100
        # ============================================================
        # Formule : (score_brut / 15) * 100
        score_sur_100 = int((score_brut / 15) * 100)
        resultat["score"] = score_sur_100
        
        # ============================================================
        # 5. DÉTERMINER LE NIVEAU DE RISQUE (seuils sur 100)
        # ============================================================
        if score_sur_100 >= 67:    # ≥ 10/15
            resultat["niveau_risque"] = "🔴 CRITIQUE"
        elif score_sur_100 >= 40:  # ≥ 6/15
            resultat["niveau_risque"] = "🟠 ÉLEVÉ"
        elif score_sur_100 >= 20:  # ≥ 3/15
            resultat["niveau_risque"] = "🟡 MOYEN"
        elif score_sur_100 >= 7:   # ≥ 1/15
            resultat["niveau_risque"] = "🟢 FAIBLE"
        else:
            resultat["niveau_risque"] = "🟢 FAIBLE"
            
    except Exception as e:
        resultat["erreur"] = str(e)
    
    return resultat

# ============================================================
# ANALYSE D'UN EMAIL
# ============================================================

def analyser_email(chemin_fichier):
    """
    Analyse un fichier .eml - Version robuste avec analyse des pièces jointes.
    """
    
    resultat = {
        "fichier": os.path.basename(chemin_fichier),
        "from": "Non spécifié",
        "to": "Non spécifié",
        "subject": "Non spécifié",
        "date": "Non spécifié",
        "message_id": "Non spécifié",
        "corps": "",
        "urls": [],
        "pieces_jointes": [],
        "erreur": None,
        "debug": []
    }
    
    try:
        with open(chemin_fichier, 'rb') as fichier_eml:
            contenu_brut = fichier_eml.read()
            resultat["debug"].append(f"Fichier lu : {len(contenu_brut)} octets")
            message = BytesParser(policy=policy.default).parsebytes(contenu_brut)
        
        resultat["from"] = message.get('From', 'Non spécifié')
        resultat["to"] = message.get('To', 'Non spécifié')
        resultat["subject"] = message.get('Subject', 'Non spécifié')
        resultat["date"] = message.get('Date', 'Non spécifié')
        resultat["message_id"] = message.get('Message-ID', 'Non spécifié')
        
        domaine_expediteur = extraire_domaine_expediteur(resultat["from"])
        resultat["domaine_expediteur"] = domaine_expediteur
        
        # ============================================================
        # EXTRACTION DES PIÈCES JOINTES
        # ============================================================
        pieces = extraire_pieces_jointes(message)
        pieces_analysees = []
        for piece in pieces:
            analyse = analyser_piece_jointe(
                piece["nom"],
                piece.get("contenu", b""),
                piece.get("taille", 0)
            )
            pieces_analysees.append(analyse)
        resultat["pieces_jointes"] = pieces_analysees
        
        # ============================================================
        # EXTRACTION DU CORPS
        # ============================================================
        corps_complet = ""
        
        try:
            corps_plain = message.get_body(preferencelist=('plain',))
            if corps_plain:
                contenu = corps_plain.get_content()
                if contenu and len(contenu.strip()) > 0:
                    corps_complet += contenu
        except:
            pass
        
        try:
            corps_html = message.get_body(preferencelist=('html',))
            if corps_html:
                contenu = corps_html.get_content()
                if contenu and len(contenu.strip()) > 0:
                    contenu_nettoye = re.sub(r'<[^>]+>', ' ', contenu)
                    contenu_nettoye = html.unescape(contenu_nettoye)
                    contenu_nettoye = re.sub(r'\s+', ' ', contenu_nettoye)
                    corps_complet += " " + contenu_nettoye
        except:
            pass
        
        if not corps_complet or len(corps_complet.strip()) < 10:
            try:
                if message.is_multipart():
                    for part in message.walk():
                        if part.get_content_type() in ['text/plain', 'text/html']:
                            try:
                                contenu_part = part.get_content()
                                if contenu_part and len(contenu_part.strip()) > 0:
                                    if part.get_content_type() == 'text/html':
                                        contenu_part = re.sub(r'<[^>]+>', ' ', contenu_part)
                                        contenu_part = html.unescape(contenu_part)
                                    contenu_part = re.sub(r'\s+', ' ', contenu_part)
                                    corps_complet += " " + contenu_part
                            except:
                                pass
                else:
                    contenu = message.get_content()
                    if contenu and len(contenu.strip()) > 0:
                        contenu = re.sub(r'<[^>]+>', ' ', contenu)
                        contenu = html.unescape(contenu)
                        contenu = re.sub(r'\s+', ' ', contenu)
                        corps_complet += contenu
            except:
                pass
        
        if not corps_complet or len(corps_complet.strip()) < 10:
            try:
                texte_brut = contenu_brut.decode('utf-8', errors='ignore')
                match = re.search(r'\r?\n\r?\n(.*)', texte_brut, re.DOTALL)
                if match:
                    corps_brut = match.group(1)
                    corps_brut = re.sub(r'<[^>]+>', ' ', corps_brut)
                    corps_brut = html.unescape(corps_brut)
                    corps_brut = re.sub(r'\s+', ' ', corps_brut)
                    corps_complet += corps_brut
            except:
                pass
        
        resultat["corps"] = corps_complet
        
        # Extraire les URLs
        urls_trouvees = extraire_urls(corps_complet)
        
        urls_completes = []
        for url in urls_trouvees:
            urls_completes.append(url)
            urls_cachees = extraire_urls_parametres(url)
            urls_completes.extend(urls_cachees)
        
        urls_uniques = []
        for url in urls_completes:
            if url not in urls_uniques:
                urls_uniques.append(url)
        
        resultat["urls"] = urls_uniques
        
    except Exception as e:
        resultat["erreur"] = str(e)
    
    return resultat

# ============================================================
# EXPORT DU RAPPORT EN HTML
# ============================================================

def generer_nom_fichier_rapport():
    """
    Génère un nom de fichier unique pour le rapport HTML avec date/heure.
    Format : rapport_YYYY-MM-DD_HH-MM-SS.html
    """
    maintenant = datetime.datetime.now()
    date_str = maintenant.strftime("%Y-%m-%d_%H-%M-%S")
    return f"rapport_{date_str}.html"

def generer_rapport_html(resultats_globaux, toutes_urls, compteur, pieces_globales=None):
    """
    Génère un rapport HTML professionnel dans le dossier 'rapports'.
    Le nom du fichier inclut la date et l'heure.
    """
    
    # Créer le dossier rapports s'il n'existe pas
    dossier_rapports = "rapports"
    if not os.path.exists(dossier_rapports):
        os.makedirs(dossier_rapports)
        print(f"📁 Dossier '{dossier_rapports}' créé.")
    
    # Générer le nom du fichier
    nom_fichier = generer_nom_fichier_rapport()
    chemin_complet = os.path.join(dossier_rapports, nom_fichier)
    
    # Compter les rapports existants
    rapports_existants = glob.glob(os.path.join(dossier_rapports, "*.html"))
    numero_rapport = len(rapports_existants) + 1
    
    # Compter les niveaux de risque
    niveaux = {'CRITIQUE': 0, 'ÉLEVÉ': 0, 'MOYEN': 0, 'FAIBLE': 0}
    for r in resultats_globaux:
        if 'niveau_risque' in r:
            niveau = r['niveau_risque']
            if 'CRITIQUE' in niveau:
                niveaux['CRITIQUE'] += 1
            elif 'ÉLEVÉ' in niveau:
                niveaux['ÉLEVÉ'] += 1
            elif 'MOYEN' in niveau:
                niveaux['MOYEN'] += 1
            else:
                niveaux['FAIBLE'] += 1
    
    # Compter les pièces jointes suspectes
    pieces_suspectes = 0
    pieces_totales = 0
    if pieces_globales:
        for pieces in pieces_globales:
            pieces_totales += len(pieces)
            for piece in pieces:
                if piece.get("est_suspect", False):
                    pieces_suspectes += 1
    
    # Créer les lignes du tableau des domaines
    domaines_rows = ""
    for domaine, count in compteur.most_common():
        domaines_rows += f"<tr><td>{domaine}</td><td>{count}</td></tr>\n"
    
    # Créer les détails des URLs
    urls_details = ""
    for r in resultats_globaux:
        niveau_classe = 'low'
        if 'CRITIQUE' in r['niveau_risque']:
            niveau_classe = 'critical'
        elif 'ÉLEVÉ' in r['niveau_risque']:
            niveau_classe = 'high'
        elif 'MOYEN' in r['niveau_risque']:
            niveau_classe = 'medium'
        
        signes_list = "".join([f'<li>{signe}</li>' for signe in r.get('signes_phishing', [])])
        
        urls_details += f'''
        <div class="email-block {niveau_classe}">
            <p><strong>URL :</strong> <a href="{r['url']}" target="_blank">{r['url']}</a></p>
            <p><strong>🌐 Domaine :</strong> {r['domaine']}</p>
            <p><strong>⚠️ Niveau de risque :</strong> <span class="risk-{niveau_classe}">{r['niveau_risque']}</span> (score: {r['score']}%)</p>
            <p><strong>📌 Signes détectés :</strong></p>
            <ul>{signes_list}</ul>
        </div>
        '''
    
    maintenant = datetime.datetime.now()
    
    # Section pièces jointes
    pieces_section = ""
    if pieces_globales and pieces_totales > 0:
        pieces_rows = ""
        for pieces in pieces_globales:
            for piece in pieces:
                classification = piece.get("classification", "✅ SÛR")
                signes = ", ".join(piece.get("signes", [])) if piece.get("signes") else "Aucun signe"
                pieces_rows += f'''
                <tr>
                    <td>{piece["nom"]}</td>
                    <td>{piece["taille"]} octets</td>
                    <td>{piece["extension"]}</td>
                    <td>{piece["hash_md5"][:16]}...</td>
                    <td>{classification}</td>
                    <td>{signes}</td>
                </tr>
                '''
        
        pieces_section = f'''
        <h2>📎 Pièces jointes analysées</h2>
        <p><strong>Total :</strong> {pieces_totales} pièces jointes | <strong>Suspectes :</strong> {pieces_suspectes}</p>
        <table>
            <tr>
                <th>Nom</th>
                <th>Taille</th>
                <th>Extension</th>
                <th>Hash MD5</th>
                <th>Classification</th>
                <th>Signes</th>
            </tr>
            {pieces_rows}
        </table>
        '''
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport d'Analyse de Phishing #{numero_rapport}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #34495e; margin-top: 30px; }}
            .summary {{ background: #ecf0f1; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
            .stat-box {{ padding: 15px; border-radius: 8px; flex: 1; min-width: 150px; text-align: center; color: white; }}
            .stat-box.critical {{ background: #e74c3c; }}
            .stat-box.high {{ background: #e67e22; }}
            .stat-box.medium {{ background: #f1c40f; color: #333; }}
            .stat-box.low {{ background: #2ecc71; }}
            .stat-box.total {{ background: #3498db; }}
            .stat-box.urls {{ background: #9b59b6; }}
            .stat-box.attachments {{ background: #e67e22; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #34495e; color: white; }}
            .footer {{ text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 0.9em; }}
            .risk-critical {{ color: #e74c3c; font-weight: bold; }}
            .risk-high {{ color: #e67e22; font-weight: bold; }}
            .risk-medium {{ color: #f1c40f; font-weight: bold; }}
            .risk-low {{ color: #2ecc71; font-weight: bold; }}
            .email-block {{ background: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 4px; }}
            .email-block.critical {{ border-left-color: #e74c3c; }}
            .email-block.high {{ border-left-color: #e67e22; }}
            .email-block.medium {{ border-left-color: #f1c40f; }}
            .email-block.low {{ border-left-color: #2ecc71; }}
            .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
            .badge-critical {{ background: #e74c3c; color: white; }}
            .badge-high {{ background: #e67e22; color: white; }}
            .badge-medium {{ background: #f1c40f; color: #333; }}
            .badge-low {{ background: #2ecc71; color: white; }}
            tr.dangerous {{ background: #fde8e8; }}
            tr.dangerous td {{ color: #c0392b; }}
            tr.risky {{ background: #fff3cd; }}
            tr.risky td {{ color: #856404; }}
            tr.safe {{ background: #d4edda; }}
            tr.safe td {{ color: #155724; }}
            tr.unknown {{ background: #f8d7da; }}
            tr.unknown td {{ color: #721c24; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Rapport d'Analyse de Phishing <span class="badge badge-low">#{numero_rapport}</span></h1>
            <p><strong>📅 Date :</strong> {maintenant.strftime("%d/%m/%Y")}</p>
            <p><strong>🕐 Heure :</strong> {maintenant.strftime("%H:%M:%S")}</p>
            <p><strong>👤 Analyse réalisée par :</strong> Jamal Jabrane</p>
            
            <div class="summary">
                <h2>📊 Résumé</h2>
                <div class="stats">
                    <div class="stat-box total">📧 {len(resultats_globaux)} URLs analysées</div>
                    <div class="stat-box urls">🔗 {len(set(toutes_urls))} URLs uniques</div>
                    <div class="stat-box attachments">📎 {pieces_totales} pièces jointes</div>
                    <div class="stat-box critical">🔴 {niveaux['CRITIQUE']} CRITIQUES</div>
                    <div class="stat-box high">🟠 {niveaux['ÉLEVÉ']} ÉLEVÉS</div>
                    <div class="stat-box medium">🟡 {niveaux['MOYEN']} MOYENS</div>
                    <div class="stat-box low">🟢 {niveaux['FAIBLE']} FAIBLES</div>
                </div>
            </div>
            
            <h2>🏷️ Domaines rencontrés</h2>
            <table>
                <tr><th>Domaine</th><th>Fréquence</th></tr>
                {domaines_rows}
            </table>
            
            {pieces_section}
            
            <h2>📧 Détail des URLs analysées</h2>
            {urls_details}
            
            <div class="footer">
                <p>Rapport généré automatiquement par Phishing Email Analyzer</p>
                <p>Jamal Jabrane - Projet PPP 2025-2026</p>
                <p style="font-size: 0.8em; color: #95a5a6;">Fichier : {nom_fichier}</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Écrire le fichier
    with open(chemin_complet, 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    print(f"✅ Rapport HTML généré : {chemin_complet}")
    print(f"   📊 Rapport n°{numero_rapport} - {maintenant.strftime('%d/%m/%Y %H:%M:%S')}")
    return chemin_complet

# ============================================================
# ANALYSE DU DOSSIER
# ============================================================

def analyser_dossier_emails(dossier="emails"):
    """
    Analyse tous les fichiers .eml présents dans un dossier.
    """
    
    print("="*80)
    print("🔍 ANALYSE DE PHISHING - RAPPORT DÉTAILLÉ")
    print("="*80)
    
    chemin_dossier = os.path.join(os.path.dirname(__file__), dossier)
    
    if not os.path.exists(chemin_dossier):
        print(f"❌ Erreur : Le dossier '{dossier}' n'existe pas.")
        return
    
    fichiers_eml = glob.glob(os.path.join(chemin_dossier, "*.eml"))
    
    if not fichiers_eml:
        print(f"❌ Aucun fichier .eml trouvé dans le dossier '{dossier}'.")
        return
    
    print(f"\n📂 {len(fichiers_eml)} fichier(s) trouvé(s) :\n")
    
    toutes_urls = []
    resultats_globaux = []
    toutes_pieces = []
    
    for i, chemin_fichier in enumerate(fichiers_eml, 1):
        print(f"{'═'*80}")
        print(f"📧 EMAIL N°{i} : {os.path.basename(chemin_fichier)}")
        print(f"{'═'*80}")
        
        resultat = analyser_email(chemin_fichier)
        
        if resultat["erreur"]:
            print(f"❌ Erreur : {resultat['erreur']}")
            continue
        
        print(f"📩 De      : {resultat['from']}")
        print(f"📨 À       : {resultat['to']}")
        print(f"📝 Objet   : {resultat['subject']}")
        print(f"📅 Date    : {resultat['date']}")
        print(f"🌐 Domaine expéditeur : {resultat.get('domaine_expediteur', 'N/A')}")
        
        # Afficher les pièces jointes
        pieces = resultat.get("pieces_jointes", [])
        if pieces:
            print(f"\n📎 Pièces jointes ({len(pieces)}) :")
            for piece in pieces:
                classification = piece.get("classification", "✅ SÛR")
                signes = ", ".join(piece.get("signes", [])) if piece.get("signes") else "Aucun signe"
                print(f"   - {piece['nom']} ({piece['taille']} octets) - {classification}")
                if piece.get("signes"):
                    for signe in piece["signes"]:
                        print(f"      {signe}")
            toutes_pieces.append(pieces)
        
        urls = resultat["urls"]
        
        if urls:
            print(f"\n🔗 URLs trouvées ({len(urls)}) :")
            for j, url in enumerate(urls, 1):
                analyse = analyser_url(url, 
                                       resultat["from"], 
                                       resultat.get('domaine_expediteur', ''))
                
                print(f"\n   {j}. {url}")
                print(f"      🌐 Domaine        : {analyse['domaine']}")
                print(f"      ⚠️  Niveau de risque : {analyse['niveau_risque']} (score: {analyse['score']}%)")
                
                if analyse["est_whitelist"]:
                    print("      ✅ Domaine dans la liste blanche (sécurisé)")
                elif analyse["est_tracking"]:
                    print("      ✅ Domaine de tracking légitime")
                
                if analyse["signes_phishing"]:
                    print("      📌 Signes détectés :")
                    for signe in analyse["signes_phishing"]:
                        print(f"         {signe}")
                
                if analyse["parametres_redirection"]:
                    print("      🔄 Redirections :")
                    for param in analyse["parametres_redirection"]:
                        print(f"         {param}")
                
                toutes_urls.append(analyse["domaine"])
                resultats_globaux.append(analyse)
        else:
            print("\n🔗 Aucune URL trouvée.")
        
        if resultat["corps"] and len(resultat["corps"].strip()) > 10:
            print(f"\n📄 Extrait du corps :")
            corps_nettoye = re.sub(r'\s+', ' ', resultat["corps"])
            print(f"   {corps_nettoye[:300]}...")
            print(f"   📊 Longueur : {len(corps_nettoye)} caractères")
        
        print()
    
    # Statistiques globales
    print("="*80)
    print("📊 STATISTIQUES GLOBALES")
    print("="*80)
    
    if toutes_urls:
        print(f"\n🔗 Total des URLs uniques : {len(set(toutes_urls))}")
        
        compteur = Counter(toutes_urls)
        print("\n🏷️  Domaines rencontrés :")
        for domaine, count in compteur.most_common():
            print(f"   - {domaine} : {count} fois")
        
        niveaux = [r["niveau_risque"] for r in resultats_globaux if "niveau_risque" in r]
        if niveaux:
            print("\n⚠️  Répartition des risques :")
            for niveau in set(niveaux):
                print(f"   - {niveau} : {niveaux.count(niveau)} URL(s)")
    
    # Statistiques des pièces jointes
    if toutes_pieces:
        total_pieces = sum(len(p) for p in toutes_pieces)
        total_dangereuses = sum(1 for p in toutes_pieces for piece in p if piece.get("est_dangereux", False))
        total_risque = sum(1 for p in toutes_pieces for piece in p if piece.get("est_risque", False))
        total_inconnues = sum(1 for p in toutes_pieces for piece in p if piece.get("classification") == "🟡 INCONNU")
        
        print(f"\n📎 Pièces jointes :")
        print(f"   - Total : {total_pieces}")
        print(f"   - 🔴 Dangereuses : {total_dangereuses}")
        print(f"   - 🟠 À risque : {total_risque}")
        print(f"   - 🟡 Inconnues : {total_inconnues}")
        print(f"   - ✅ Sûres : {total_pieces - total_dangereuses - total_risque - total_inconnues}")
    
    # Générer le rapport HTML
    if toutes_urls or toutes_pieces:
        generer_rapport_html(resultats_globaux, toutes_urls, compteur, toutes_pieces)
    
    print("\n" + "="*80)
    print("✅ Analyse terminée.")
    print("="*80)

# ============================================================
# POINT D'ENTRÉE
# ============================================================

if __name__ == "__main__":
    analyser_dossier_emails()