# app.py
# Interface Streamlit pour l'analyseur de phishing - Version avec score global et boutons interactifs

import streamlit as st
import os
import tempfile
import pandas as pd
import re
import webbrowser
from collections import Counter
from analyseur import analyser_email, analyser_url, extraire_domaine_expediteur

# ============================================================
# CONFIGURATION DE LA PAGE
# ============================================================

st.set_page_config(
    page_title="🔍 Analyseur de Phishing",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS PERSONNALISÉ
# ============================================================

st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 20px;
        background: linear-gradient(135deg, #1a2a6c, #b21f1f, #fdbb2d);
        border-radius: 10px;
        color: white;
        margin-bottom: 30px;
    }
    .score-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px 20px;
        background: #f8f9fa;
        border-radius: 10px;
        margin: 10px 0 20px 0;
        border: 2px solid #ddd;
    }
    .score-badge {
        font-size: 2em;
        font-weight: bold;
        padding: 10px 25px;
        border-radius: 50px;
        color: white;
    }
    .score-badge.critical { background: #e74c3c; }
    .score-badge.high { background: #e67e22; }
    .score-badge.medium { background: #f1c40f; color: #333; }
    .score-badge.low { background: #2ecc71; }
    .score-badge.safe { background: #3498db; }
    .risk-critical { color: #e74c3c; font-weight: bold; }
    .risk-high { color: #e67e22; font-weight: bold; }
    .risk-medium { color: #f1c40f; font-weight: bold; }
    .risk-low { color: #2ecc71; font-weight: bold; }
    .stat-box {
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        margin: 5px;
    }
    .stat-box.total { background: #3498db; color: white; }
    .stat-box.critical { background: #e74c3c; color: white; }
    .stat-box.high { background: #e67e22; color: white; }
    .stat-box.medium { background: #f1c40f; color: #333; }
    .stat-box.low { background: #2ecc71; color: white; }
    .stat-box.attachments { background: #9b59b6; color: white; }
    .email-card {
        background: #f8f9fa;
        border-left: 4px solid #3498db;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
    }
    .email-card.critical { border-left-color: #e74c3c; }
    .email-card.high { border-left-color: #e67e22; }
    .email-card.medium { border-left-color: #f1c40f; }
    .email-card.low { border-left-color: #2ecc71; }
    .email-card.safe { border-left-color: #3498db; }
    .attachment-safe { color: #2ecc71; font-weight: bold; }
    .attachment-dangerous { color: #e74c3c; font-weight: bold; }
    .attachment-risky { color: #e67e22; font-weight: bold; }
    .attachment-unknown { color: #f1c40f; font-weight: bold; }
    .url-btn {
        display: inline-block;
        padding: 5px 15px;
        margin: 5px;
        border-radius: 5px;
        text-decoration: none;
        font-size: 0.9em;
    }
    .url-btn.safe { background: #2ecc71; color: white; }
    .url-btn.warning { background: #f1c40f; color: #333; }
    .url-btn.danger { background: #e74c3c; color: white; }
    .url-btn.info { background: #3498db; color: white; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# EN-TÊTE
# ============================================================

st.markdown("""
<div class="main-header">
    <h1>🔍 Analyseur d'Emails de Phishing</h1>
    <p>Analysez vos emails en quelques secondes et détectez les tentatives de phishing</p>
</div>
""", unsafe_allow_html=True)

# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.header("📤 Import")
    st.markdown("---")
    
    fichier = st.file_uploader(
        "Déposez un fichier .eml",
        type=['eml'],
        help="Téléchargez un email au format .eml pour l'analyser"
    )
    
    st.markdown("---")
    st.header("ℹ️ Informations")
    st.markdown("""
    - **Développé par :** Jamal Jabrane
    - **Projet :** PPP 2025-2026
    - **Version :** 2.0
    """)
    
    st.markdown("---")
    with st.expander("📖 Guide d'utilisation"):
        st.markdown("""
        1. Téléchargez un email au format `.eml`
        2. L'analyse se lance automatiquement
        3. Consultez les résultats :
           - **Score global** de l'email
           - URLs détectées avec leur risque
           - Pièces jointes analysées
           - Signes de phishing
        4. Cliquez sur les boutons pour **ouvrir les URLs** en toute sécurité
        """)

# ============================================================
# FONCTIONS DE L'APPLICATION
# ============================================================

def calculer_score_global(analyse):
    """
    Calcule un score global pour l'email basé sur l'analyse des URLs.
    Retourne : score (%), niveau, message
    """
    urls = analyse.get("urls", [])
    if not urls:
        return 0, "🟢 FAIBLE", "Aucune URL trouvée"
    
    scores = []
    for url in urls:
        analyse_url = analyser_url(url, analyse.get("from", ""), analyse.get("domaine_expediteur", ""))
        scores.append(analyse_url.get("score", 0))
    
    # Score moyen
    score_moyen = sum(scores) // len(scores)
    
    # Déterminer le niveau
    if score_moyen >= 67:
        niveau = "🔴 CRITIQUE"
        message = "⚠️ Cet email présente un risque très élevé de phishing"
    elif score_moyen >= 40:
        niveau = "🟠 ÉLEVÉ"
        message = "⚠️ Cet email présente plusieurs signes suspects"
    elif score_moyen >= 20:
        niveau = "🟡 MOYEN"
        message = "🔍 Cet email présente quelques signes suspects"
    elif score_moyen >= 7:
        niveau = "🟢 FAIBLE"
        message = "✅ Cet email semble globalement sûr"
    else:
        niveau = "🟢 FAIBLE"
        message = "✅ Cet email semble sûr"
    
    return score_moyen, niveau, message

def afficher_statistiques(analyse):
    """
    Affiche les statistiques de l'analyse dans la sidebar.
    """
    if not analyse or "erreur" in analyse:
        return
    
    urls = analyse.get("urls", [])
    pieces = analyse.get("pieces_jointes", [])
    
    st.sidebar.markdown("---")
    st.sidebar.header("📊 Statistiques")
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        st.metric("🔗 URLs", len(urls))
    with col2:
        st.metric("📎 Pièces", len(pieces))
    
    # Score global
    score, niveau, message = calculer_score_global(analyse)
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("🎯 Score global")
    
    # Déterminer la couleur du score
    if score >= 67:
        color = "🔴"
    elif score >= 40:
        color = "🟠"
    elif score >= 20:
        color = "🟡"
    else:
        color = "🟢"
    
    st.sidebar.markdown(f"### {color} {score}%")
    st.sidebar.markdown(f"**{niveau}**")
    
    # Analyse des URLs
    if urls:
        niveaux = []
        for url in urls:
            analyse_url = analyser_url(url, analyse.get("from", ""), analyse.get("domaine_expediteur", ""))
            niveaux.append(analyse_url.get("niveau_risque", "🟢 FAIBLE"))
        
        compteur = Counter(niveaux)
        
        st.sidebar.subheader("Répartition des risques")
        col1, col2 = st.sidebar.columns(2)
        with col1:
            st.metric("🔴 CRITIQUE", compteur.get("🔴 CRITIQUE", 0))
            st.metric("🟠 ÉLEVÉ", compteur.get("🟠 ÉLEVÉ", 0))
        with col2:
            st.metric("🟡 MOYEN", compteur.get("🟡 MOYEN", 0))
            st.metric("🟢 FAIBLE", compteur.get("🟢 FAIBLE", 0))
    
    # Analyse des pièces jointes
    if pieces:
        st.sidebar.subheader("Pièces jointes")
        for piece in pieces:
            classification = piece.get("classification", "✅ SÛR")
            st.sidebar.write(f"- {piece['nom']} : {classification}")

def afficher_en_tete_score(analyse):
    """
    Affiche l'en-tête avec le score global.
    """
    score, niveau, message = calculer_score_global(analyse)
    
    # Déterminer la classe CSS
    if score >= 67:
        classe = "critical"
    elif score >= 40:
        classe = "high"
    elif score >= 20:
        classe = "medium"
    else:
        classe = "low"
    
    # Déterminer l'icône
    if score >= 67:
        icon = "🚨"
    elif score >= 40:
        icon = "⚠️"
    elif score >= 20:
        icon = "🔍"
    else:
        icon = "✅"
    
    st.markdown(f"""
    <div class="score-header">
        <div>
            <h3 style="margin: 0;">📊 Score global de l'email</h3>
            <p style="margin: 0; color: #7f8c8d; font-size: 0.9em;">{message}</p>
        </div>
        <div>
            <span class="score-badge {classe}">{icon} {score}%</span>
            <span style="font-size: 1.2em; margin-left: 10px;">{niveau}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def afficher_analyse(resultat):
    """
    Affiche les résultats de l'analyse.
    """
    if not resultat:
        return
    
    if "erreur" in resultat and resultat["erreur"]:
        st.error(f"❌ Erreur lors de l'analyse : {resultat['erreur']}")
        return
    
    # ============================================================
    # SCORE GLOBAL DANS L'EN-TÊTE
    # ============================================================
    
    afficher_en_tete_score(resultat)
    
    # ============================================================
    # INFORMATIONS DE L'EMAIL
    # ============================================================
    
    st.subheader("📧 Informations de l'email")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**📩 De :** {resultat.get('from', 'Non spécifié')}")
        st.markdown(f"**📨 À :** {resultat.get('to', 'Non spécifié')}")
    with col2:
        st.markdown(f"**📝 Objet :** {resultat.get('subject', 'Non spécifié')}")
        st.markdown(f"**📅 Date :** {resultat.get('date', 'Non spécifié')}")
    
    st.markdown(f"**🌐 Domaine expéditeur :** {resultat.get('domaine_expediteur', 'N/A')}")
    
    st.markdown("---")
    
    # ============================================================
    # PIÈCES JOINTES
    # ============================================================
    
    pieces = resultat.get("pieces_jointes", [])
    if pieces:
        st.subheader("📎 Pièces jointes")
        
        # Créer un DataFrame pour l'affichage
        data = []
        for piece in pieces:
            classification = piece.get("classification", "✅ SÛR")
            signes = ", ".join(piece.get("signes", [])) if piece.get("signes") else "Aucun"
            
            # Déterminer la couleur
            if "DANGEREUX" in classification:
                badge = "🔴 DANGEREUX"
            elif "À RISQUE" in classification:
                badge = "🟠 À RISQUE"
            elif "INCONNU" in classification:
                badge = "🟡 INCONNU"
            else:
                badge = "✅ SÛR"
            
            data.append({
                "Nom": piece["nom"],
                "Taille": f"{piece['taille']} octets",
                "Extension": piece["extension"],
                "Hash MD5": piece["hash_md5"][:16] + "..." if piece.get("hash_md5") else "N/A",
                "Classification": badge,
                "Signes": signes
            })
        
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
        
        st.markdown("---")
    
    # ============================================================
    # URLS AVEC BOUTONS INTERACTIFS
    # ============================================================
    
    urls = resultat.get("urls", [])
    if urls:
        st.subheader(f"🔗 URLs trouvées ({len(urls)})")
        
        for i, url in enumerate(urls, 1):
            analyse = analyser_url(url, resultat.get("from", ""), resultat.get("domaine_expediteur", ""))
            
            # Déterminer la classe CSS
            niveau = analyse.get("niveau_risque", "🟢 FAIBLE")
            if "CRITIQUE" in niveau:
                classe = "critical"
                btn_class = "danger"
            elif "ÉLEVÉ" in niveau:
                classe = "high"
                btn_class = "warning"
            elif "MOYEN" in niveau:
                classe = "medium"
                btn_class = "warning"
            else:
                classe = "low"
                btn_class = "safe"
            
            # Afficher la carte
            with st.container():
                st.markdown(f"""
                <div class="email-card {classe}">
                    <p><strong>{i}. {url}</strong></p>
                    <p>🌐 Domaine : {analyse.get('domaine', 'N/A')}</p>
                    <p>⚠️ Niveau de risque : <span class="risk-{classe}">{niveau}</span> (score: {analyse.get('score', 0)}%)</p>
                """, unsafe_allow_html=True)
                
                # Boutons interactifs
                col1, col2, col3 = st.columns([1, 1, 3])
                
                with col1:
                    # Bouton pour ouvrir l'URL dans un nouvel onglet (en sécurité)
                    # On utilise un lien HTML car Streamlit ne permet pas d'ouvrir directement
                    st.markdown(f"""
                    <a href="{url}" target="_blank" class="url-btn {btn_class}" style="text-decoration: none; display: inline-block;">
                        🔗 Ouvrir
                    </a>
                    """, unsafe_allow_html=True)
                
                with col2:
                    # Bouton pour copier l'URL
                    if st.button(f"📋 Copier", key=f"copy_{i}"):
                        st.code(url, language="text")
                        st.success("URL copiée !")
                
                with col3:
                    # Afficher un avertissement si l'URL est suspecte
                    if "CRITIQUE" in niveau or "ÉLEVÉ" in niveau:
                        st.warning("⚠️ Cette URL est suspecte. Ouvrez-la avec prudence !")
                    elif "MOYEN" in niveau:
                        st.info("🔍 Cette URL présente des signes suspects. Vérifiez avant d'ouvrir.")
                    else:
                        st.success("✅ Cette URL semble sûre.")
                
                if analyse.get("est_whitelist", False):
                    st.markdown("✅ **Domaine dans la liste blanche (sécurisé)**")
                elif analyse.get("est_tracking", False):
                    st.markdown("✅ **Domaine de tracking légitime**")
                
                if analyse.get("signes_phishing"):
                    st.markdown("**📌 Signes détectés :**")
                    for signe in analyse["signes_phishing"]:
                        st.markdown(f"- {signe}")
                
                if analyse.get("parametres_redirection"):
                    st.markdown("**🔄 Redirections :**")
                    for param in analyse["parametres_redirection"]:
                        st.markdown(f"- {param}")
                
                st.markdown("</div>", unsafe_allow_html=True)
                st.markdown("---")
    else:
        st.info("ℹ️ Aucune URL trouvée dans cet email.")
    
    # ============================================================
    # CORPS DE L'EMAIL
    # ============================================================
    
    with st.expander("📄 Corps de l'email"):
        if resultat.get("corps"):
            corps = resultat["corps"]
            # Nettoyer le corps pour l'affichage
            corps_nettoye = re.sub(r'\s+', ' ', corps)
            st.text(corps_nettoye[:5000])
            if len(corps_nettoye) > 5000:
                st.text("... (tronqué)")
        else:
            st.info("Corps non accessible")

def analyser_fichier(fichier):
    """
    Analyse un fichier .eml et retourne les résultats.
    """
    try:
        # Sauvegarder temporairement
        with tempfile.NamedTemporaryFile(delete=False, suffix='.eml') as tmp:
            tmp.write(fichier.getvalue())
            tmp_path = tmp.name
        
        # Analyser
        resultat = analyser_email(tmp_path)
        
        # Nettoyer
        os.unlink(tmp_path)
        
        return resultat
    except Exception as e:
        return {"erreur": str(e)}

# ============================================================
# INTERFACE PRINCIPALE
# ============================================================

if fichier is not None:
    with st.spinner("🔍 Analyse en cours..."):
        resultat = analyser_fichier(fichier)
    
    if resultat:
        # Afficher les statistiques dans la sidebar
        afficher_statistiques(resultat)
        
        # Afficher l'analyse
        afficher_analyse(resultat)
        
        # Bouton pour télécharger le rapport
        st.markdown("---")
        if st.button("📥 Télécharger le rapport HTML"):
            # Générer le rapport HTML
            from analyseur import generer_rapport_html, generer_nom_fichier_rapport
            from collections import Counter
            
            # Préparer les données
            toutes_urls = []
            resultats_globaux = []
            for url in resultat.get("urls", []):
                analyse = analyser_url(url, resultat.get("from", ""), resultat.get("domaine_expediteur", ""))
                toutes_urls.append(analyse["domaine"])
                resultats_globaux.append(analyse)
            
            compteur = Counter(toutes_urls)
            
            # Générer le rapport
            nom_fichier = generer_nom_fichier_rapport()
            chemin = generer_rapport_html(resultats_globaux, toutes_urls, compteur, [resultat.get("pieces_jointes", [])])
            
            # Lire le fichier généré
            with open(chemin, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            st.download_button(
                label="📄 Télécharger le rapport",
                data=html_content,
                file_name=nom_fichier,
                mime="text/html"
            )
else:
    # Message d'accueil
    st.info("👈 Téléchargez un fichier .eml dans la barre latérale pour commencer l'analyse")
    
    # Exemple de démonstration
    with st.expander("📖 Exemple d'analyse", expanded=True):
        st.markdown("""
        ### Comment fonctionne l'outil ?
        
        1. **Téléchargez** un email au format `.eml`
        2. L'outil **extrait automatiquement** :
           - Les URLs présentes dans l'email
           - Les pièces jointes
           - Les métadonnées (expéditeur, objet, date)
        3. **Analyse en profondeur** :
           - Détection des TLD suspects
           - Comparaison avec la whitelist
           - Détection des substitutions (typosquatting)
           - Analyse des redirections
        4. **Résultats clairs** :
           - Score global de l'email
           - Score de risque (0-100%) pour chaque URL
           - Niveau de risque (FAIBLE/MOYEN/ÉLEVÉ/CRITIQUE)
           - Signes de phishing détectés
           - Pièces jointes suspectes
        
        ### 🎯 Niveaux de risque
        
        | Score | Niveau | Signification |
        |-------|--------|---------------|
        | 0-6% | 🟢 FAIBLE | Domaine sécurisé ou whitelisté |
        | 7-19% | 🟢 FAIBLE | Risque minimal |
        | 20-39% | 🟡 MOYEN | Signes suspects détectés |
        | 40-66% | 🟠 ÉLEVÉ | Plusieurs signes de phishing |
        | 67-100% | 🔴 CRITIQUE | Très probablement du phishing |
        """)

# ============================================================
# PIED DE PAGE
# ============================================================

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #7f8c8d; font-size: 0.9em;">
    <p>🔒 Analyse effectuée en local - Aucune donnée n'est envoyée à l'extérieur</p>
    <p>Jamal Jabrane - Projet PPP 2025-2026</p>
</div>
""", unsafe_allow_html=True)