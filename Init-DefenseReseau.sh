#!/usr/bin/env bash
#===============================================================================
#  Init-DefenseReseau.sh
#
#  SYNOPSIS
#      Script interactif de mise en place de la defense reseau d'un
#      environnement Linux (Debian/Ubuntu) : pare-feu a zones avec DMZ
#      (nftables ou iptables, + guide OPNsense), IDS/IPS (Snort ou Suricata,
#      regles locales, tuning, threat intel), proxy de filtrage sortant
#      (Squid), reverse proxy (HAProxy ou Nginx), bastion SSH durci (ANSSI),
#      moindre privilege, evaluation Zero Trust (NIST SP 800-207) et audit
#      d'hygiene inspire des referentiels ANSSI.
#
#  DESCRIPTION
#      Outil operationnel de mise en place de la defense reseau :
#        - Interactif par menus ; volet pedagogique optionnel (--pedago) masque par defaut.
#        - Idempotent : les fichiers modifies sont sauvegardes, les objets
#          crees sont traces dans un manifeste, le script est relancable.
#        - Mode simulation (--dry-run) : montre ce qui serait fait, sans agir.
#        - Mode non-interactif (--unattended --config fichier.conf).
#        - Journalisation de chaque etape + rapport HTML final.
#        - Reinitialisation protegee par la saisie exacte du mot 'biere' :
#          restaure les fichiers sauvegardes et supprime UNIQUEMENT ce que le
#          script a cree et trace.
#
#  MODULES (objectifs pedagogiques couverts)
#      1. Concepts : moyens de defense, defense en profondeur, moindre
#         privilege, panorama et CHOIX des equipements de securite.
#      2. Zero Trust (NIST SP 800-207) : les 7 principes, evaluation de
#         maturite interactive et plan d'action operationnel.
#      3. Pare-feu a zones (nftables recommande / iptables) : politique par
#         defaut DROP, zones WAN/LAN/DMZ, NAT, redirections vers la DMZ,
#         anti-verrouillage (rollback automatique) + guide OPNsense genere.
#      4. IDS/IPS : Snort (apprentissage) ou Suricata (production), ecriture
#         de regles locales commentees, tuning (threshold/suppress),
#         sources de threat intelligence (ET Open via suricata-update).
#      5. Proxy de filtrage sortant : Squid (ACL, liste noire, journaux).
#      6. Reverse proxy : HAProxy ou Nginx (TLS, en-tetes de securite).
#      7. Bastion SSH : durcissement sshd selon le guide ANSSI OpenSSH,
#         acces par cles uniquement, fail2ban, banniere legale, ProxyJump.
#      8. Moindre privilege : sudoers granulaire, umask, services inutiles,
#         politique de mots de passe (pwquality).
#      9. Audit d'hygiene (lecture seule) : verification de l'etat du
#         systeme au regard des grands themes du Guide d'hygiene
#         informatique de l'ANSSI, avec score et recommandations.
#      R. Rapport HTML recapitulatif.
#      Z. Reinitialisation 'biere'.
#
#  USAGE
#      sudo ./Init-DefenseReseau.sh                 # interactif
#      sudo ./Init-DefenseReseau.sh --dry-run       # simulation
#      sudo ./Init-DefenseReseau.sh --unattended --config config.sample.conf
#      sudo ./Init-DefenseReseau.sh --reset         # reinitialisation 'biere'
#
#  NOTES
#      Version : 1.1.0
#      Cible   : Debian 11/12, Ubuntu 22.04/24.04 (paquets via apt)
#      Etat    : /var/lib/init-defense-reseau/ (journal, manifeste, sauvegardes)
#      Licence : MIT
#
#      ATTENTION : outil concu pour des labs, maquettes et petits
#      environnements. Testez en maquette avant toute production : un
#      pare-feu en politique DROP ou un sshd durci mal configure peut vous
#      couper l'acces (des garde-fous anti-verrouillage sont integres).
#===============================================================================

set -o pipefail

#===============================================================================
# REGION 0 : CONSTANTES
#===============================================================================
SCRIPT_NAME="Init-DefenseReseau"
SCRIPT_VERSION="1.1.0"
RESET_KEYWORD="biere"          # mot de passe symbolique du reset (sensible a la casse)

DRY_RUN=0
UNATTENDED=0
NO_COLOR=0
DO_RESET=0
PEDAGO=0            # 0 = outil operationnel (defaut) ; 1 = affiche les explications (--pedago)
CONFIG_FILE=""

# Repertoires d'etat (redefinis pour un dry-run non root : voir init_dirs)
STATE_DIR="/var/lib/init-defense-reseau"
BACKUP_DIR=""       # $STATE_DIR/sauvegardes
LOG_DIR=""          # $STATE_DIR/logs
MANIFEST=""         # $STATE_DIR/manifeste.tsv
JOURNAL=""          # $STATE_DIR/journal.log
DONE_LIST=""        # $STATE_DIR/modules-termines.list
AUDIT_TSV=""        # $STATE_DIR/audit.tsv
ZT_TSV=""           # $STATE_DIR/zerotrust.tsv
LOG_FILE=""

REPORT_DIR_DEFAULT="/root/Rapports-DefenseReseau"

declare -A BACKED_UP=()   # fichiers deja sauvegardes durant cette session

# --- Nettoyage des fichiers temporaires (meme sur Ctrl-C / kill) ---
# Tous les fichiers temporaires sont crees dans TMP_ROOT (initialise par init_dirs).
# On supprime le repertoire entier : robuste meme si new_tmp est appele en
# substitution de commande $( ) (sous-shell), cas ou un tableau serait perdu.
TMP_ROOT=""
new_tmp() {
    if [[ -n "$TMP_ROOT" ]]; then mktemp -p "$TMP_ROOT"; else mktemp; fi
}
cleanup_tmp() { [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]] && rm -rf "$TMP_ROOT" 2>/dev/null; return 0; }
trap cleanup_tmp EXIT
trap 'cleanup_tmp; exit 130' INT TERM

#===============================================================================
# REGION 1 : AFFICHAGE, SAISIE, JOURNALISATION
#===============================================================================

setup_colors() {
    if [[ $NO_COLOR -eq 1 || ! -t 1 ]]; then
        C_OFF="" C_RED="" C_GRN="" C_YEL="" C_BLU="" C_CYA="" C_BLD="" C_DIM=""
    else
        C_OFF=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
        C_BLU=$'\033[34m'; C_CYA=$'\033[36m'; C_BLD=$'\033[1m';  C_DIM=$'\033[2m'
    fi
}

log()   { [[ -n "$LOG_FILE" ]] && printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG_FILE"; }
say()   { printf '%s\n' "$*"; log "$*"; }
info()  { printf '%s\n' "${C_CYA}  i ${C_OFF}$*"; log "INFO  $*"; }
ok()    { printf '%s\n' "${C_GRN}  + ${C_OFF}$*"; log "OK    $*"; }
warn()  { printf '%s\n' "${C_YEL}  ! ${C_OFF}$*"; log "WARN  $*"; }
err()   { printf '%s\n' "${C_RED}  x ${C_OFF}$*" >&2; log "ERROR $*"; }

title() {
    printf '\n%s\n' "${C_BLD}${C_BLU}==============================================================================${C_OFF}"
    printf '%s\n'   "${C_BLD}${C_BLU}  $*${C_OFF}"
    printf '%s\n'   "${C_BLD}${C_BLU}==============================================================================${C_OFF}"
    log "=== $* ==="
}

subtitle() {
    printf '\n%s\n' "${C_BLD}--- $* ---${C_OFF}"
    log "--- $* ---"
}

journal() {
    printf '%s|%s\n' "$(date '+%F %T')" "$*" >> "$JOURNAL"
}

pause() {
    [[ $UNATTENDED -eq 1 ]] && return 0
    printf '%s' "${C_DIM}  Appuyez sur Entree pour continuer...${C_OFF}"
    read -r _
}

# teach : n'affiche le contenu (heredoc) qu'en mode pedagogique (--pedago).
# Consomme toujours stdin pour ne pas casser le flux du heredoc.
teach() { if [[ $PEDAGO -eq 1 ]]; then cat; else cat >/dev/null; fi; }

# pause_teach : ne s'arrete qu'en mode pedagogique (evite les pauses inutiles en operationnel).
pause_teach() { [[ $PEDAGO -eq 1 ]] && pause; return 0; }

# ask_yn "Question" "o|n" -> code retour 0 = oui, 1 = non
ask_yn() {
    local question="$1" def="${2:-n}" r
    if [[ $UNATTENDED -eq 1 ]]; then
        log "QUESTION $question -> reponse automatique : $def"
        [[ "$def" =~ ^[oO]$ ]] && return 0 || return 1
    fi
    while true; do
        printf '%s' "${C_BLD}$question${C_OFF} (o/n, defaut: $def) : "
        read -r r
        r="${r:-$def}"
        case "$r" in
            [oO]) return 0 ;;
            [nN]) return 1 ;;
            *) err "Reponse invalide : repondez par 'o' (oui) ou 'n' (non)." ;;
        esac
    done
}

# ask_val "Invite" "defaut" -> echo la valeur choisie
ask_val() {
    local prompt="$1" def="$2" r
    if [[ $UNATTENDED -eq 1 ]]; then
        log "SAISIE $prompt -> valeur automatique : $def"
        printf '%s' "$def"
        return 0
    fi
    printf '%s' "${C_BLD}$prompt${C_OFF} [${def}] : " >&2
    read -r r
    printf '%s' "${r:-$def}"
}

# valid_port 22 -> 0 si entier 1..65535
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

# ask_port "Invite" "defaut" -> echo un port valide (re-demande si invalide)
ask_port() {
    local prompt="$1" def="$2" p
    while true; do
        p=$(ask_val "$prompt" "$def")
        if valid_port "$p"; then printf '%s' "$p"; return 0; fi
        err "Port invalide (attendu : entier 1-65535) : '$p'"
        [[ $UNATTENDED -eq 1 ]] && { printf '%s' "$def"; return 0; }
    done
}

# ask_choice "Invite" "opt1" "opt2" ... -> echo le numero (1..n)
ask_choice() {
    local prompt="$1"; shift
    local opts=("$@") i r
    if [[ $UNATTENDED -eq 1 ]]; then printf '1'; return 0; fi
    printf '\n%s\n' "${C_BLD}$prompt${C_OFF}" >&2
    for i in "${!opts[@]}"; do
        printf '    %d) %s\n' "$((i+1))" "${opts[$i]}" >&2
    done
    while true; do
        printf '%s' "  Votre choix [1-${#opts[@]}] : " >&2
        read -r r
        if [[ "$r" =~ ^[0-9]+$ ]] && (( r >= 1 && r <= ${#opts[@]} )); then
            printf '%s' "$r"; return 0
        fi
        err "Choix invalide."
    done
}

#===============================================================================
# REGION 2 : MOTEUR (execution, fichiers, manifeste, etat)
#===============================================================================

init_dirs() {
    if [[ $EUID -ne 0 && $DRY_RUN -eq 1 ]]; then
        STATE_DIR="${TMPDIR:-/tmp}/init-defense-reseau-simulation"
    fi
    BACKUP_DIR="$STATE_DIR/sauvegardes"
    LOG_DIR="$STATE_DIR/logs"
    MANIFEST="$STATE_DIR/manifeste.tsv"
    JOURNAL="$STATE_DIR/journal.log"
    DONE_LIST="$STATE_DIR/modules-termines.list"
    AUDIT_TSV="$STATE_DIR/audit.tsv"
    ZT_TSV="$STATE_DIR/zerotrust.tsv"
    mkdir -p "$BACKUP_DIR" "$LOG_DIR" 2>/dev/null || {
        printf 'Impossible de creer %s (droits insuffisants ?)\n' "$STATE_DIR" >&2
        exit 1
    }
    touch "$MANIFEST" "$JOURNAL" "$DONE_LIST"
    LOG_FILE="$LOG_DIR/session_$(date '+%Y%m%d_%H%M%S').log"
    : > "$LOG_FILE"
    # Repertoire des fichiers temporaires (nettoye par cleanup_tmp au trap EXIT/INT/TERM)
    TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/init-defres.XXXXXX" 2>/dev/null) || TMP_ROOT=""
}

require_root() {
    if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
        err "Ce script doit etre lance en root (sudo). Utilisez --dry-run pour une simulation sans droits."
        exit 1
    fi
}

check_apt() {
    if ! command -v apt-get >/dev/null 2>&1; then
        warn "apt-get introuvable : les installations de paquets echoueront (cible : Debian/Ubuntu)."
        return 1
    fi
    return 0
}

# run_cmd "description" commande args...
run_cmd() {
    local desc="$1"; shift
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} $desc : $*"
        journal "SIMULATION : $desc"
        return 0
    fi
    log "CMD: $*"
    if "$@" >>"$LOG_FILE" 2>&1; then
        ok "$desc"
        journal "OK : $desc"
        return 0
    else
        err "$desc : ECHEC (details dans $LOG_FILE)"
        journal "ECHEC : $desc"
        return 1
    fi
}

# install_pkgs paquet1 [paquet2 ...] : n'inscrit au manifeste que les paquets
# reellement installes par le script (pour un reset fidele).
install_pkgs() {
    local p missing=()
    for p in "$@"; do
        if dpkg -s "$p" >/dev/null 2>&1; then
            info "Paquet deja present : $p"
        else
            missing+=("$p")
        fi
    done
    [[ ${#missing[@]} -eq 0 ]] && return 0
    check_apt || return 1
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} Installation des paquets : ${missing[*]}"
        return 0
    fi
    run_cmd "Mise a jour de l'index des paquets" env DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    if run_cmd "Installation : ${missing[*]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"; then
        for p in "${missing[@]}"; do manifest_add "pkg|$p"; done
        return 0
    fi
    return 1
}

manifest_add() {
    grep -qxF "$1" "$MANIFEST" 2>/dev/null && return 0
    printf '%s\n' "$1" >> "$MANIFEST"
}

# backup_file /chemin : sauvegarde horodatee + trace 'modfile' (une fois par session)
backup_file() {
    local path="$1"
    [[ -f "$path" ]] || return 0
    [[ -n "${BACKED_UP[$path]:-}" ]] && return 0
    local safe dest
    safe=$(printf '%s' "$path" | tr '/' '_')
    dest="$BACKUP_DIR/$(date '+%Y%m%d_%H%M%S')${safe}"
    cp -a "$path" "$dest"
    BACKED_UP[$path]="$dest"
    manifest_add "modfile|$path|$dest"
    info "Sauvegarde : $path -> $dest"
}

# write_file /chemin "description"  (contenu via stdin / heredoc)
write_file() {
    local path="$1" desc="$2" content existed=0
    content=$(cat)
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} Ecriture de $path ($desc, $(printf '%s\n' "$content" | wc -l) lignes)"
        journal "SIMULATION : ecriture de $path ($desc)"
        return 0
    fi
    [[ -f "$path" ]] && existed=1 && backup_file "$path"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$content" > "$path"
    [[ $existed -eq 0 ]] && manifest_add "newfile|$path"
    ok "Fichier ecrit : $path ($desc)"
    journal "OK : ecriture de $path ($desc)"
}

mark_done()  { grep -qxF "$1" "$DONE_LIST" 2>/dev/null || printf '%s\n' "$1" >> "$DONE_LIST"; }
is_done()    { grep -qxF "$1" "$DONE_LIST" 2>/dev/null; }
done_mark()  { is_done "$1" && printf '%s' "${C_GRN}[fait]${C_OFF}" || printf '%s' "      "; }

# Detection d'aides reseau
default_iface() { ip -o route show default 2>/dev/null | awk '{print $5; exit}'; }
iface_network() {
    # iface_network eth0 -> 192.168.1.0/24 (premiere adresse IPv4) ; echec si aucune
    ip -o -4 addr show dev "$1" 2>/dev/null | awk '{print $4; exit}' | grep .
}
list_ifaces() { ip -o link show 2>/dev/null | awk -F': ' '$2 !~ /^lo/ {print $2}' | cut -d'@' -f1; }

#===============================================================================
# REGION 3 : MODULE 1 - CONCEPTS ET CHOIX DES EQUIPEMENTS
#===============================================================================

concepts_defense() {
    subtitle "Defense en profondeur et moindre privilege"
    cat <<'TXT'
  DEFENSE EN PROFONDEUR
    Principe herite du militaire : ne jamais dependre d'une seule barriere.
    Chaque couche ralentit, detecte ou bloque l'attaquant ; la compromission
    d'une couche ne doit pas donner acces a tout le systeme.

      Internet --> [Pare-feu peripherie] --> [DMZ : services exposes]
                       |                         |  (IDS/IPS ecoute ici)
                       v                         v
                  [Pare-feu interne] --> [LAN : postes, serveurs internes]
                       |
                  [Bastion SSH] --> administration tracee et controlee

    Couches typiques : filtrage reseau (pare-feu, segmentation, DMZ),
    detection (IDS/IPS, journaux, SIEM), controle applicatif (proxy,
    reverse proxy, WAF), controle des acces (bastion, MFA, moindre
    privilege), durcissement des hotes, sauvegardes testees.

  MOINDRE PRIVILEGE
    Chaque utilisateur, service ou flux ne recoit QUE les droits strictement
    necessaires a sa tache, pour la duree necessaire. Applications :
      - reseau  : politique pare-feu par defaut DROP, on autorise flux par flux ;
      - systeme : sudo granulaire (une commande, pas 'ALL'), comptes de service
        sans shell, umask restrictif ;
      - la DMZ n'a JAMAIS le droit d'initier une connexion vers le LAN.
TXT
    pause
}

concepts_equipements() {
    subtitle "Panorama des equipements de securite (logiques et physiques)"
    cat <<'TXT'
  EQUIPEMENT            ROLE                                  EXEMPLES
  --------------------  ------------------------------------  --------------------
  Pare-feu stateful     Filtre les flux par zone/etat de      nftables, iptables,
                        connexion. Coeur de la segmentation.  OPNsense, pfSense
  Pare-feu NGFW/UTM     + inspection applicative, IDS/IPS,    OPNsense+Suricata,
                        filtrage URL integres.                 Fortinet, Stormshield*
  IDS (detection)       Ecoute le trafic (copie/port mirror)  Suricata, Snort, Zeek
                        et ALERTE sur signatures/anomalies.
  IPS (prevention)      En coupure : BLOQUE le trafic         Suricata (nfqueue),
                        malveillant. Risque de faux positifs.  Snort inline
  Proxy sortant         Point de passage oblige du web        Squid
                        sortant : filtrage, journalisation.
  Reverse proxy         Facade unique devant les serveurs     Nginx, HAProxy,
                        web : TLS, en-tetes, repartition.      Traefik
  WAF                   Reverse proxy specialise anti         ModSecurity + CRS,
                        attaques web (injections, XSS).        Nginx App Protect
  Bastion / PAM         Point d'entree unique et trace de     OpenSSH durci,
                        l'administration.                      Teleport, Guacamole
  VPN / acces distant   Chiffre l'acces des nomades.          WireGuard, OpenVPN,
                                                               IPsec (guide ANSSI)
  NAC / 802.1X          Controle QUI se branche au reseau     switch manageable +
                        physique (port par port).              RADIUS (FreeRADIUS)
  SIEM / journaux       Centralise et correle les journaux.   Wazuh, ELK, Graylog
  * produits qualifies ANSSI : voir le catalogue "Visas de securite" de l'ANSSI.

  PHYSIQUE : la securite logique repose sur des choix physiques ; local
  technique ferme, switchs manageables (VLAN, port-security), TAP reseau ou
  port mirror pour l'IDS, liens redondants, onduleur.
TXT
    pause
}

concepts_assistant() {
    subtitle "Assistant de choix des equipements"
    say "  5 questions pour esquisser une architecture adaptee a votre contexte."
    local q1 q2 q3 q4 q5
    q1=$(ask_choice "Taille du reseau a proteger ?" \
        "Petit lab / TPE (< 20 machines)" "PME (20 a 200 machines)" "Plus grand / multi-sites")
    q2=$(ask_choice "Exposez-vous des services sur Internet (web, mail...) ?" \
        "Non" "Oui, 1 ou 2 services" "Oui, plusieurs services critiques")
    q3=$(ask_choice "Des utilisateurs distants / teletravail ?" "Non" "Oui")
    q4=$(ask_choice "Donnees sensibles (RGPD, sante, industriel...) ?" "Non / peu" "Oui")
    q5=$(ask_choice "Capacite d'administration securite ?" \
        "Limitee (temps partiel)" "Une personne dediee ou presta" "Equipe securite")

    subtitle "Recommandations"
    say "  Socle commun (toujours) :"
    say "   - pare-feu stateful en peripherie, politique par defaut DROP (module 3) ;"
    say "   - journalisation centralisee et sauvegardes testees ;"
    say "   - bastion SSH pour toute administration (module 7) ;"
    say "   - moindre privilege systeme et reseau (module 8)."
    if [[ "$q2" != "1" ]]; then
        say "  Services exposes :"
        say "   - DMZ dediee derriere le pare-feu, jamais de flux DMZ -> LAN (module 3) ;"
        say "   - reverse proxy en facade (TLS + en-tetes de securite, module 6) ;"
        [[ "$q2" == "3" ]] && say "   - ajoutez un WAF (ModSecurity + OWASP CRS) devant les applications critiques."
    fi
    if [[ "$q1" == "1" ]]; then
        say "  Petit environnement : une appliance OPNsense (pare-feu + Suricata + proxy)"
        say "   concentre l'essentiel sur une seule machine, administrable en web."
    else
        say "  A partir de la PME : separez les roles (pare-feu dedie, IDS sur TAP/mirror,"
        say "   proxy et reverse proxy sur des VM distinctes) et segmentez en VLAN (802.1X si possible)."
    fi
    [[ "$q3" == "2" ]] && say "  Teletravail : VPN WireGuard/IPsec + MFA ; interdisez l'exposition directe de RDP/SSH."
    [[ "$q4" == "2" ]] && say "  Donnees sensibles : chiffrement au repos, cloisonnement renforce, IDS obligatoire (module 4), demarche Zero Trust (module 2)."
    case "$q5" in
        1) say "  Administration limitee : privilegiez OPNsense (tout-en-un, interface web) et les regles gerees (ET Open) plutot que des regles maison nombreuses." ;;
        2) say "  Une personne dediee : Suricata + Squid + bastion auto-heberges sont a votre portee ; ce script vous sert de trame." ;;
        3) say "  Equipe : ajoutez SIEM (Wazuh/ELK), NAC 802.1X, revue reguliere des regles et exercices d'intrusion." ;;
    esac
    journal "Module 1 : assistant de choix execute (taille=$q1 exposition=$q2 distant=$q3 sensible=$q4 admin=$q5)"
    pause
}

concepts_referentiels() {
    subtitle "Referentiels ANSSI a connaitre (cyber.gouv.fr)"
    cat <<'TXT'
  - Guide d'hygiene informatique (42 mesures) : le socle. Le module 9 de ce
    script en verifie les grands themes applicables a une machine Linux.
  - Recommandations relatives a l'interconnexion d'un SI a Internet :
    architecture en zones, DMZ, proxys, passerelle Internet securisee.
  - Recommandations pour la definition d'une politique de filtrage reseau
    d'un pare-feu : methode pour ecrire des regles (deny all, matrice de flux).
  - Recommandations pour un usage securise d'(Open)SSH : la reference du
    module 7 (bastion) : algorithmes, authentification par cles, AllowGroups.
  - Recommandations de securite relatives a IPsec / TLS : pour les VPN et
    le reverse proxy.
  - Recommandations pour la journalisation : quoi journaliser, combien de
    temps, comment centraliser.
  - Le modele Zero Trust (avis scientifique ANSSI) + NIST SP 800-207 :
    voir module 2.
TXT
    pause
}

module_concepts() {
    title "MODULE 1 : Choix des equipements de securite"
    # Mode operationnel (defaut) : uniquement l'assistant d'architecture (actionnable).
    # Les fiches explicatives (defense en profondeur, panorama, referentiels) ne
    # s'affichent qu'avec --pedago.
    if [[ $PEDAGO -eq 0 ]]; then
        concepts_assistant
        mark_done "concepts"
        journal "Module 1 : assistant d'architecture"
        return 0
    fi
    local c
    while true; do
        c=$(ask_choice "Que souhaitez-vous consulter ?" \
            "Defense en profondeur et moindre privilege" \
            "Panorama des equipements (logiques et physiques)" \
            "Assistant de choix des equipements (5 questions)" \
            "Referentiels ANSSI a connaitre" \
            "Retour au menu principal")
        case "$c" in
            1) concepts_defense ;;
            2) concepts_equipements ;;
            3) concepts_assistant ;;
            4) concepts_referentiels ;;
            5) break ;;
        esac
        [[ $UNATTENDED -eq 1 ]] && break
    done
    mark_done "concepts"
    journal "Module 1 (concepts) consulte"
}

#===============================================================================
# REGION 4 : MODULE 2 - ZERO TRUST (NIST SP 800-207)
#===============================================================================

# 7 principes (tenets) du NIST SP 800-207, section 2.1
ZT_TENETS=(
    "1. Toute donnee et tout service est une ressource a proteger"
    "2. Toute communication est securisee, quel que soit l'emplacement reseau"
    "3. L'acces est accorde par session, jamais de facon permanente"
    "4. L'acces depend d'une politique dynamique (identite, appareil, contexte)"
    "5. L'integrite et la posture de securite de chaque actif sont surveillees"
    "6. Authentification et autorisation sont strictes et reevaluees en continu"
    "7. On collecte un maximum d'informations pour ameliorer la posture"
)

# Questionnaire : ZT_QT = index du principe (0-6), ZT_QQ = question,
# ZT_QA0/1/2 = reponses valant 0, 1 et 2 points.
ZT_QT=(0 0 1 1 2 2 3 3 4 4 5 5 6 6)
ZT_QQ=(
    "Disposez-vous d'un inventaire a jour des machines, services et donnees ?"
    "Les donnees sensibles sont-elles identifiees et classifiees ?"
    "Les flux INTERNES (LAN) sont-ils chiffres (TLS, SSH) comme les flux externes ?"
    "Le reseau est-il segmente (VLAN/zones) avec filtrage entre segments ?"
    "Les acces d'administration sont-ils limites dans le temps (session, expiration) ?"
    "Un utilisateur authentifie sur un service a-t-il acces aux autres sans controle ?"
    "Les regles d'acces tiennent-elles compte du contexte (appareil, heure, lieu) ?"
    "Existe-t-il une revue reguliere des droits (qui a acces a quoi) ?"
    "L'etat de sante des postes (MAJ, antivirus, chiffrement) est-il verifie ?"
    "Les equipements non conformes sont-ils isoles ou restreints automatiquement ?"
    "Le MFA (double facteur) est-il deploye pour les comptes sensibles ?"
    "Les privileges d'administration passent-ils par un bastion trace ?"
    "Les journaux (reseau, systeme, applicatif) sont-ils centralises ?"
    "Ces journaux sont-ils reellement exploites (alertes, revue, IDS) ?"
)
ZT_QA0=(
    "Non / pas formalise" "Non" "Non, l'interne est en clair" "Non, reseau a plat"
    "Non, acces permanents" "Oui, acces libre une fois dans le reseau" "Non, IP source uniquement"
    "Jamais" "Non" "Non" "Non" "Non, acces direct aux serveurs" "Non" "Non"
)
ZT_QA1=(
    "Partiel / manuel" "Partiellement" "Partiellement (services principaux)" "Quelques VLAN sans filtrage strict"
    "Pour certains comptes" "Controles partiels" "Partiellement" "Ponctuellement" "Manuellement"
    "Manuellement" "Pour certains comptes" "Bastion partiel / non trace" "Partiellement" "Ponctuellement"
)
ZT_QA2=(
    "Oui, inventaire tenu a jour" "Oui, classification etablie" "Oui, chiffrement generalise"
    "Oui, zones + politique de filtrage" "Oui, sessions limitees et reevaluees"
    "Non, chaque acces est reverifie" "Oui, politique contextuelle" "Oui, revue periodique formalisee"
    "Oui, verification automatisee" "Oui, isolement automatique" "Oui, MFA generalise"
    "Oui, bastion obligatoire et trace" "Oui, centralisation en place" "Oui, supervision active (SIEM/IDS)"
)

ZT_RECO=(
    "Etablissez l'inventaire (machines, services, donnees) et classifiez : c'est le prealable a toute politique Zero Trust."
    "Chiffrez aussi les flux internes (TLS partout, SSH durci - module 7) et segmentez le reseau en zones filtrees (module 3)."
    "Passez a des acces par session : expiration des sessions, comptes a duree limitee, pas de droits permanents."
    "Construisez des politiques d'acces dynamiques : MFA, controle de l'appareil, regles par contexte (NAC 802.1X, acces conditionnel)."
    "Surveillez la posture des actifs : gestion des MAJ, verification de conformite, isolement des machines non conformes."
    "Renforcez l'authentification : MFA sur les comptes sensibles, bastion trace pour l'administration (module 7), reevaluation continue."
    "Collectez et EXPLOITEZ les journaux : centralisation (rsyslog/SIEM), IDS (module 4), revue reguliere des alertes."
)

# Action concrete du principe 1 (connaitre ses ressources) : inventaire local
zt_inventory() {
    local dir="${CFG_REPORT_DIR:-$REPORT_DIR_DEFAULT}"
    local out="$dir/inventaire_$(hostname)_$(date '+%Y%m%d_%H%M%S').txt"
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} Generation de l'inventaire local dans $dir"
        journal "SIMULATION : inventaire local"
        return 0
    fi
    mkdir -p "$dir"
    {
        printf 'INVENTAIRE LOCAL - %s - %s\n' "$(hostname)" "$(date '+%F %T')"
        printf 'Genere par %s v%s (Zero Trust, principe 1 : connaitre ses ressources)\n\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '== Systeme ==\n  %s - noyau %s\n\n' "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-inconnu}")" "$(uname -r)"
        printf '== Adresses IP ==\n'
        ip -o -4 addr show 2>/dev/null | awk '{print "  "$2" : "$4}'
        printf '\n== Services en ecoute (ports exposes) ==\n'
        ss -tulnp 2>/dev/null | sed 's/^/  /'
        printf '\n== Services actives au demarrage ==\n'
        systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | sed 's/^/  /'
        printf '\n== Paquets installes ==\n  %s paquets\n' "$(dpkg -l 2>/dev/null | grep -c '^ii')"
    } > "$out"
    manifest_add "newfile|$out"
    ok "Inventaire genere : $out"
    journal "Zero Trust : inventaire local genere ($out)"
}

module_zerotrust() {
    title "MODULE 2 : Zero Trust - NIST SP 800-207"
    teach <<'TXT'
  Le Zero Trust part d'un constat : la confiance implicite accordee au reseau
  interne ("je suis dans le LAN donc j'ai le droit") est la faille exploitee
  par la majorite des attaques modernes (mouvement lateral apres une premiere
  compromission). Le NIST SP 800-207 formalise 7 principes : plus aucune
  confiance implicite, chaque acces est verifie (identite + appareil +
  contexte), accorde au plus juste et reevalue en continu.

  Composants logiques du modele NIST :
    - PDP (Policy Decision Point)   : decide d'accorder ou non l'acces ;
    - PEP (Policy Enforcement Point): applique la decision (pare-feu, proxy,
      bastion, agent...) - les modules 3, 5, 6 et 7 de ce script sont des PEP.

  Approches de deploiement (SP 800-207 sect. 3) :
    - gouvernance d'identite renforcee (IAM + MFA au coeur des decisions) ;
    - micro-segmentation (pare-feux entre chaque zone/ressource - module 3) ;
    - perimetres definis par logiciel (SDP / ZTNA).

  Application operationnelle : c'est une DEMARCHE progressive, pas un produit.
  L'evaluation suivante situe votre maturite sur chaque principe.
TXT
    pause_teach
    if ! ask_yn "Lancer l'evaluation de maturite Zero Trust (14 questions) ?" "o"; then
        return 0
    fi

    local -a tenet_score tenet_max
    local i t r
    for i in 0 1 2 3 4 5 6; do tenet_score[$i]=0; tenet_max[$i]=0; done

    for i in "${!ZT_QQ[@]}"; do
        t=${ZT_QT[$i]}
        r=$(ask_choice "Q$((i+1))/14 - ${ZT_QQ[$i]}" "${ZT_QA0[$i]}" "${ZT_QA1[$i]}" "${ZT_QA2[$i]}")
        tenet_score[$t]=$(( tenet_score[$t] + r - 1 ))
        tenet_max[$t]=$(( tenet_max[$t] + 2 ))
    done

    subtitle "Resultats par principe"
    : > "$ZT_TSV"
    local total=0 totalmax=0 pct level
    local -a weak=(0 0 0 0 0 0 0)
    for i in 0 1 2 3 4 5 6; do
        total=$(( total + tenet_score[$i] ))
        totalmax=$(( totalmax + tenet_max[$i] ))
        pct=$(( tenet_max[$i] > 0 ? 100 * tenet_score[$i] / tenet_max[$i] : 0 ))
        if   (( pct >= 85 )); then level="Optimal"
        elif (( pct >= 65 )); then level="Avance"
        elif (( pct >= 35 )); then level="Initial"
        else                       level="Traditionnel"; fi
        printf '%s\t%s\t%s%%\t%s\n' "${ZT_TENETS[$i]}" "${tenet_score[$i]}/${tenet_max[$i]}" "$pct" "$level" >> "$ZT_TSV"
        say "  ${ZT_TENETS[$i]}"
        if (( pct >= 65 )); then
            ok "  Score ${tenet_score[$i]}/${tenet_max[$i]} ($pct %) - niveau $level"
        else
            warn "  Score ${tenet_score[$i]}/${tenet_max[$i]} ($pct %) - niveau $level"
            say  "     -> ${ZT_RECO[$i]}"
            weak[$i]=1
        fi
    done
    pct=$(( totalmax > 0 ? 100 * total / totalmax : 0 ))
    subtitle "Maturite globale : $total/$totalmax ($pct %)"
    say "  Echelle (inspiree du Zero Trust Maturity Model de la CISA) :"
    say "   < 35 % Traditionnel | 35-64 % Initial | 65-84 % Avance | >= 85 % Optimal"
    say "  Les resultats sont conserves et repris dans le rapport (module R)."
    printf 'GLOBAL\t%s/%s\t%s%%\t-\n' "$total" "$totalmax" "$pct" >> "$ZT_TSV"

    # --- Plan d'action OPERATIONNEL : chaque action est appliquee ou ignoree ---
    subtitle "Plan d'action operationnel (appliquez ou ignorez chaque action)"
    local acted=0
    if [[ ${weak[0]} -eq 1 ]]; then
        acted=1
        if ask_yn "Principe 1 - Generer MAINTENANT un inventaire local (IP, ports exposes, services, paquets) ?" "o"; then
            zt_inventory
        fi
    fi
    if [[ ${weak[1]} -eq 1 ]]; then
        acted=1
        if ask_yn "Principe 2 - Lancer le module 3 (segmentation : pare-feu de zones) maintenant ?" "n"; then
            module_firewall
        fi
    fi
    if [[ ${weak[2]} -eq 1 || ${weak[3]} -eq 1 || ${weak[5]} -eq 1 ]]; then
        acted=1
        if ask_yn "Principes 3/4/6 - Lancer le module 7 (bastion SSH : acces traces, sessions limitees, cles) ?" "n"; then
            module_bastion
        fi
        info "Pour le MFA et l'acces conditionnel complet : solution IAM (Keycloak, Authelia, FreeIPA) - hors perimetre de ce script."
    fi
    if [[ ${weak[4]} -eq 1 ]]; then
        acted=1
        if ask_yn "Principe 5 - Activer les mises a jour automatiques (unattended-upgrades) maintenant ?" "o"; then
            apply_fix unattended
        fi
    fi
    if [[ ${weak[6]} -eq 1 ]]; then
        acted=1
        if ask_yn "Principe 7 - Installer la journalisation d'audit (rsyslog + auditd) maintenant ?" "o"; then
            apply_fix rsyslog
            apply_fix auditd
        fi
        if ask_yn "Principe 7 - Lancer le module 4 (IDS : visibilite reseau) maintenant ?" "n"; then
            module_ids
        fi
    fi
    [[ $acted -eq 0 ]] && ok "Tous les principes sont au moins au niveau Avance : pas d'action prioritaire."

    mark_done "zerotrust"
    journal "Module 2 : evaluation Zero Trust realisee ($total/$totalmax, $pct %)"
    pause
}

#===============================================================================
# REGION 5 : MODULE 3 - PARE-FEU (nftables / iptables) AVEC ZONES ET DMZ
#===============================================================================

fw_pedagogie() {
    teach <<'TXT'
  METHODE (guide ANSSI "politique de filtrage d'un pare-feu") :
    1. politique par defaut : TOUT INTERDIRE (policy drop) ;
    2. matrice de flux : lister les flux LEGITIMES (qui -> quoi, quel port) ;
    3. une regle par flux, la plus precise possible (zone, IP, port) ;
    4. journaliser ce qui est bloque (avec limitation de debit) ;
    5. relire et purger les regles regulierement.

  ZONES :
    WAN (Internet, non fiable) | DMZ (services exposes) | LAN (interne)
    Regles d'or : le WAN n'atteint que la DMZ (ports publies uniquement) ;
    la DMZ n'initie JAMAIS de flux vers le LAN ; le LAN sort via des points
    controles (proxy - module 5).

  ANTI-VERROUILLAGE : ce module applique les regles puis vous demande de
  confirmer que votre acces fonctionne toujours ; sans confirmation sous
  60 secondes, l'ancien jeu de regles est restaure automatiquement.
TXT
}

fw_ask_forwards() {
    # Remplit le tableau global FW_FORWARDS ("port_ext:ip_dmz:port_int")
    FW_FORWARDS=()
    [[ $UNATTENDED -eq 1 ]] && {
        local f
        for f in ${CFG_FW_FORWARDS:-}; do FW_FORWARDS+=("$f"); done
        return 0
    }
    say ""
    say "  Publications de services de la DMZ (redirections depuis le WAN)."
    say "  Format : port_externe:ip_dmz:port_interne (ex: 443:192.168.20.10:443)"
    local entry
    while true; do
        printf '%s' "  Redirection a ajouter (vide pour terminer) : "
        read -r entry
        [[ -z "$entry" ]] && break
        if [[ "$entry" =~ ^[0-9]+:[0-9.]+:[0-9]+$ ]]; then
            FW_FORWARDS+=("$entry")
            ok "Redirection enregistree : $entry"
        else
            err "Format invalide (attendu port:ip:port)."
        fi
    done
}

fw_generate_nft() {
    # $1=mode (hote|routeur) ; ecrit le ruleset dans le fichier $2
    local mode="$1" out="$2"
    {
        printf '#!/usr/sbin/nft -f\n'
        printf '# Genere par %s v%s le %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION" "$(date '+%F %T')"
        printf '# Politique par defaut DROP - une regle par flux legitime (methode ANSSI)\n'
        printf 'flush ruleset\n\n'
        printf 'table inet filtre {\n'
        printf '    chain entree {\n'
        printf '        type filter hook input priority 0; policy drop;\n'
        printf '        ct state established,related accept comment "reponses aux connexions etablies"\n'
        printf '        ct state invalid drop comment "paquets invalides"\n'
        printf '        iif "lo" accept comment "boucle locale"\n'
        printf '        icmp type echo-request limit rate 4/second accept comment "ping limite"\n'
        printf '        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept comment "IPv6 minimum vital"\n'
        if [[ "$mode" == "routeur" ]]; then
            printf '        iifname "%s" tcp dport %s ct state new limit rate 6/minute accept comment "SSH admin depuis le LAN uniquement"\n' "$FW_LAN_IF" "$FW_SSH_PORT"
        else
            printf '        tcp dport %s ct state new limit rate 6/minute accept comment "SSH (limite : 6 nouvelles connexions/minute)"\n' "$FW_SSH_PORT"
            local p
            for p in $FW_EXTRA_TCP; do
                printf '        tcp dport %s accept comment "service autorise (TCP %s)"\n' "$p" "$p"
            done
            for p in $FW_EXTRA_UDP; do
                printf '        udp dport %s accept comment "service autorise (UDP %s)"\n' "$p" "$p"
            done
        fi
        printf '        log prefix "[FW-ENTREE-REJET] " limit rate 5/minute counter comment "journalise puis drop (policy)"\n'
        printf '    }\n\n'
        printf '    chain transfert {\n'
        printf '        type filter hook forward priority 0; policy drop;\n'
        if [[ "$mode" == "routeur" ]]; then
            printf '        ct state established,related accept\n'
            printf '        ct state invalid drop\n'
            printf '        iifname "%s" oifname "%s" accept comment "LAN vers Internet"\n' "$FW_LAN_IF" "$FW_WAN_IF"
            printf '        iifname "%s" oifname "%s" accept comment "LAN vers DMZ (administration/consommation)"\n' "$FW_LAN_IF" "$FW_DMZ_IF"
            printf '        iifname "%s" oifname "%s" tcp dport { 80, 443 } accept comment "DMZ vers Internet : HTTP/HTTPS (MAJ)"\n' "$FW_DMZ_IF" "$FW_WAN_IF"
            printf '        iifname "%s" oifname "%s" udp dport 53 accept comment "DMZ : DNS"\n' "$FW_DMZ_IF" "$FW_WAN_IF"
            printf '        iifname "%s" oifname "%s" tcp dport 53 accept comment "DMZ : DNS (TCP)"\n' "$FW_DMZ_IF" "$FW_WAN_IF"
            printf '        # Volontairement AUCUNE regle DMZ -> LAN : une DMZ compromise ne doit pas atteindre le LAN\n'
            local f pext ip pint
            for f in "${FW_FORWARDS[@]}"; do
                IFS=':' read -r pext ip pint <<< "$f"
                printf '        iifname "%s" oifname "%s" ip daddr %s tcp dport %s ct state new accept comment "service publie (WAN:%s -> DMZ)"\n' "$FW_WAN_IF" "$FW_DMZ_IF" "$ip" "$pint" "$pext"
            done
        else
            printf '        # Machine hote : aucun routage\n'
        fi
        printf '        log prefix "[FW-TRANSFERT-REJET] " limit rate 5/minute counter\n'
        printf '    }\n\n'
        printf '    chain sortie {\n'
        printf '        type filter hook output priority 0; policy accept;\n'
        printf '        # Durcissement possible : passer en policy drop et lister les flux sortants\n'
        printf '    }\n'
        printf '}\n'
        if [[ "$mode" == "routeur" ]]; then
            printf '\ntable ip nat {\n'
            printf '    chain prerouting {\n'
            printf '        type nat hook prerouting priority dstnat;\n'
            local f pext ip pint
            for f in "${FW_FORWARDS[@]}"; do
                IFS=':' read -r pext ip pint <<< "$f"
                printf '        iifname "%s" tcp dport %s dnat to %s:%s comment "publication DMZ"\n' "$FW_WAN_IF" "$pext" "$ip" "$pint"
            done
            printf '    }\n'
            printf '    chain postrouting {\n'
            printf '        type nat hook postrouting priority srcnat;\n'
            printf '        oifname "%s" masquerade comment "NAT de sortie"\n' "$FW_WAN_IF"
            printf '    }\n'
            printf '}\n'
        fi
    } > "$out"
}

fw_generate_iptables() {
    # $1=mode ; ecrit un fichier au format iptables-restore dans $2
    local mode="$1" out="$2"
    {
        printf '# Genere par %s v%s le %s (format iptables-restore)\n' "$SCRIPT_NAME" "$SCRIPT_VERSION" "$(date '+%F %T')"
        if [[ "$mode" == "routeur" ]]; then
            printf '*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n'
            local f pext ip pint
            for f in "${FW_FORWARDS[@]}"; do
                IFS=':' read -r pext ip pint <<< "$f"
                printf -- '-A PREROUTING -i %s -p tcp --dport %s -j DNAT --to-destination %s:%s\n' "$FW_WAN_IF" "$pext" "$ip" "$pint"
            done
            printf -- '-A POSTROUTING -o %s -j MASQUERADE\n' "$FW_WAN_IF"
            printf 'COMMIT\n'
        fi
        printf '*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n'
        printf -- '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
        printf -- '-A INPUT -m conntrack --ctstate INVALID -j DROP\n'
        printf -- '-A INPUT -i lo -j ACCEPT\n'
        printf -- '-A INPUT -p icmp --icmp-type echo-request -m limit --limit 4/second -j ACCEPT\n'
        if [[ "$mode" == "routeur" ]]; then
            printf -- '-A INPUT -i %s -p tcp --dport %s -m conntrack --ctstate NEW -m limit --limit 6/minute -j ACCEPT\n' "$FW_LAN_IF" "$FW_SSH_PORT"
        else
            printf -- '-A INPUT -p tcp --dport %s -m conntrack --ctstate NEW -m limit --limit 6/minute -j ACCEPT\n' "$FW_SSH_PORT"
            local p
            for p in $FW_EXTRA_TCP; do printf -- '-A INPUT -p tcp --dport %s -j ACCEPT\n' "$p"; done
            for p in $FW_EXTRA_UDP; do printf -- '-A INPUT -p udp --dport %s -j ACCEPT\n' "$p"; done
        fi
        printf -- '-A INPUT -m limit --limit 5/minute -j LOG --log-prefix "[FW-ENTREE-REJET] "\n'
        if [[ "$mode" == "routeur" ]]; then
            printf -- '-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
            printf -- '-A FORWARD -m conntrack --ctstate INVALID -j DROP\n'
            printf -- '-A FORWARD -i %s -o %s -j ACCEPT\n' "$FW_LAN_IF" "$FW_WAN_IF"
            printf -- '-A FORWARD -i %s -o %s -j ACCEPT\n' "$FW_LAN_IF" "$FW_DMZ_IF"
            printf -- '-A FORWARD -i %s -o %s -p tcp -m multiport --dports 80,443 -j ACCEPT\n' "$FW_DMZ_IF" "$FW_WAN_IF"
            printf -- '-A FORWARD -i %s -o %s -p udp --dport 53 -j ACCEPT\n' "$FW_DMZ_IF" "$FW_WAN_IF"
            printf -- '-A FORWARD -i %s -o %s -p tcp --dport 53 -j ACCEPT\n' "$FW_DMZ_IF" "$FW_WAN_IF"
            printf '# Volontairement AUCUNE regle DMZ -> LAN\n'
            local f pext ip pint
            for f in "${FW_FORWARDS[@]}"; do
                IFS=':' read -r pext ip pint <<< "$f"
                printf -- '-A FORWARD -i %s -o %s -d %s -p tcp --dport %s -m conntrack --ctstate NEW -j ACCEPT\n' "$FW_WAN_IF" "$FW_DMZ_IF" "$ip" "$pint"
            done
            printf -- '-A FORWARD -m limit --limit 5/minute -j LOG --log-prefix "[FW-TRANSFERT-REJET] "\n'
        fi
        printf 'COMMIT\n'
    } > "$out"
}

fw_generate_ip6tables() {
    # $1=mode ; socle IPv6 protecteur (format ip6tables-restore) dans $2.
    # Objectif : ne pas laisser l'INPUT IPv6 ouvert quand on choisit iptables.
    # On garde ICMPv6 (indispensable a IPv6) et le port SSH (anti-verrouillage).
    local mode="$1" out="$2"
    {
        printf '# Genere par %s v%s le %s (IPv6, format ip6tables-restore)\n' "$SCRIPT_NAME" "$SCRIPT_VERSION" "$(date '+%F %T')"
        printf '*filter\n'
        if [[ "$mode" == "routeur" ]]; then
            # FORWARD laisse a ACCEPT : filtrer le routage IPv6 sans le tester couperait
            # la connectivite v6 du LAN. On protege l'hote (INPUT) et on avertit.
            printf ':INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n'
        else
            printf ':INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n'
        fi
        printf -- '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
        printf -- '-A INPUT -m conntrack --ctstate INVALID -j DROP\n'
        printf -- '-A INPUT -i lo -j ACCEPT\n'
        printf -- '-A INPUT -p ipv6-icmp -j ACCEPT\n'
        printf -- '-A INPUT -p tcp --dport %s -m conntrack --ctstate NEW -m limit --limit 6/minute -j ACCEPT\n' "$FW_SSH_PORT"
        if [[ "$mode" == "hote" ]]; then
            local p
            for p in $FW_EXTRA_TCP; do printf -- '-A INPUT -p tcp --dport %s -j ACCEPT\n' "$p"; done
            for p in $FW_EXTRA_UDP; do printf -- '-A INPUT -p udp --dport %s -j ACCEPT\n' "$p"; done
        fi
        printf -- '-A INPUT -m limit --limit 5/minute -j LOG --log-prefix "[FW6-ENTREE-REJET] "\n'
        printf 'COMMIT\n'
    } > "$out"
}

fw_apply_with_rollback() {
    # $1=moteur (nft|iptables) $2=fichier de regles IPv4/inet $3=(optionnel) fichier ip6tables
    local engine="$1" rules="$2" v6rules="${3:-}" sav sav6="" ans
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} Application du jeu de regles $engine (avec rollback 60 s)."
        return 0
    fi
    sav=$(new_tmp)
    if [[ "$engine" == "nft" ]]; then
        # La table 'inet' couvre IPv4 ET IPv6 : rien de separe a faire.
        nft list ruleset > "$sav" 2>/dev/null
        if ! run_cmd "Application du jeu de regles nftables" nft -f "$rules"; then return 1; fi
    else
        iptables-save > "$sav" 2>/dev/null
        if ! run_cmd "Application du jeu de regles iptables (IPv4)" iptables-restore "$rules"; then return 1; fi
        # IPv6 : sans regles ip6tables, l'INPUT IPv6 reste grand ouvert (politique ACCEPT
        # par defaut). On applique un socle protecteur, restaurable par le meme rollback.
        if [[ -n "$v6rules" ]] && command -v ip6tables >/dev/null 2>&1; then
            sav6=$(new_tmp)
            ip6tables-save > "$sav6" 2>/dev/null
            run_cmd "Application du jeu de regles ip6tables (IPv6)" ip6tables-restore "$v6rules" \
                || warn "Application IPv6 en echec : verifiez ip6tables (protection IPv6 non garantie)."
        fi
    fi
    warn "ANTI-VERROUILLAGE : verifiez MAINTENANT que votre acces (SSH...) fonctionne."
    printf '%s' "${C_BLD}  Conserver ces regles ? Tapez 'o' sous 60 s, sinon RESTAURATION automatique : ${C_OFF}"
    ans=""
    read -t 60 -r ans || true
    if [[ "$ans" =~ ^[oO]$ ]]; then
        ok "Regles confirmees et conservees."
        journal "Pare-feu : nouvelles regles $engine confirmees"
        rm -f "$sav" "$sav6"
        return 0
    fi
    warn "Pas de confirmation : restauration de l'ancien jeu de regles..."
    if [[ "$engine" == "nft" ]]; then
        nft flush ruleset
        nft -f "$sav" 2>>"$LOG_FILE" || warn "Ruleset precedent vide : pare-feu remis a zero (tout ouvert)."
    else
        iptables-restore "$sav" 2>>"$LOG_FILE"
        [[ -n "$sav6" ]] && ip6tables-restore "$sav6" 2>>"$LOG_FILE"
    fi
    journal "Pare-feu : regles $engine annulees (anti-verrouillage)"
    rm -f "$sav" "$sav6"
    return 1
}

fw_opnsense_guide() {
    local dir="${CFG_REPORT_DIR:-$REPORT_DIR_DEFAULT}"
    local out="$dir/guide-opnsense.md"
    [[ $DRY_RUN -eq 0 ]] && mkdir -p "$dir"
    write_file "$out" "guide pas-a-pas OPNsense (zones + DMZ + IDS)" <<'GUIDE'
# Guide OPNsense : pare-feu de zones avec DMZ

OPNsense est une distribution pare-feu open source (FreeBSD) administree en
web. C'est l'equivalent "appliance" de ce que le module 3 met en place avec
nftables : memes principes (deny all, zones, matrice de flux), avec en plus
IDS/IPS Suricata, proxy et VPN integres.

## 1. Installation et interfaces
1. Telechargez l'image sur opnsense.org (verifier l'empreinte SHA-256) ;
   installez sur une machine/VM avec 3 cartes reseau.
2. A la console, assignez : WAN (vers Internet), LAN (reseau interne),
   OPT1 -> renommez-la **DMZ** (Interfaces > Assignments).
3. Adressage type : LAN 192.168.10.1/24, DMZ 192.168.20.1/24.
4. Premiere connexion web depuis le LAN : https://192.168.10.1
   (changez immediatement le mot de passe, activez le MFA de l'interface).

## 2. Alias (Firewall > Aliases)
Creez des alias pour rendre les regles lisibles et maintenables :
- `SRV_WEB_DMZ`  : 192.168.20.10 (votre serveur web en DMZ)
- `PORTS_WEB`    : 80, 443
- `ADMIN_LAN`    : IP des postes d'administration

## 3. Politique de zones (Firewall > Rules)
Rappel : OPNsense evalue les regles par interface d'ENTREE, premiere
correspondance gagne, et tout ce qui n'est pas autorise est bloque (deny
implicite en fin de liste) - conforme a la methode ANSSI.

**LAN** (trafic venant du LAN) :
1. autoriser LAN -> DMZ ports utiles (PORTS_WEB vers SRV_WEB_DMZ) ;
2. autoriser LAN -> WAN (ou mieux : uniquement vers le proxy - module 5) ;
3. autoriser ADMIN_LAN -> `This Firewall` port 443 (administration) ;
4. tout le reste est bloque implicitement.

**DMZ** :
1. BLOQUER DMZ -> reseau LAN (regle explicite "Block", destination
   `LAN net`, a placer EN PREMIER et journalisee) ;
2. autoriser DMZ -> WAN ports 80/443/53 (mises a jour, DNS) ;
3. tout le reste bloque.

**WAN** : aucune regle "allow" manuelle sauf besoins VPN ; les publications
se font par NAT (ci-dessous). Laissez le blocage des reseaux prives/bogons.

## 4. Publication d'un service DMZ (Firewall > NAT > Port Forward)
- Interface WAN, TCP, port de destination 443 -> rediriger vers
  `SRV_WEB_DMZ:443`. Laissez "Filter rule association: add associated rule"
  pour creer automatiquement la regle de filtrage liee.

## 5. IDS/IPS integre (Services > Intrusion Detection)
1. cochez Enabled ; interfaces surveillees : WAN et DMZ ;
2. "IPS mode" pour bloquer (commencez SANS, en detection seule) ;
3. Download : abonnez-vous aux regles **ET Open** (threat intelligence
   gratuite), puis activez les categories utiles (scan, malware, web) ;
4. onglet Alerts : traitez les alertes, affinez (desactivation de sid
   bruyants = tuning, comme au module 4).

## 6. Bonnes pratiques d'exploitation
- **Anti-verrouillage** : gardez la regle par defaut qui autorise le LAN a
  joindre l'interface web avant de durcir, et testez chaque regle.
- Sauvegardez la configuration (System > Configuration > Backups) apres
  chaque changement valide - export XML chiffre hors de la machine.
- Mettez a jour regulierement (System > Firmware).
- Journalisez les regles de blocage et exportez les journaux vers un
  collecteur (syslog) - cf. recommandations de journalisation ANSSI.
GUIDE
    ok "Guide OPNsense genere : $out"
}

module_firewall() {
    title "MODULE 3 : Pare-feu a zones (nftables / iptables) avec DMZ"
    fw_pedagogie
    pause_teach

    local engine mode c
    c=$(ask_choice "Quel moteur de filtrage ?" \
        "nftables (recommande : successeur d'iptables, syntaxe unifiee)" \
        "iptables (compatibilite / apprentissage de l'historique)" \
        "Seulement generer le guide OPNsense (appliance dediee)")
    if [[ "$c" == "3" ]]; then
        fw_opnsense_guide
        mark_done "parefeu"
        pause
        return 0
    fi
    [[ "$c" == "1" ]] && engine="nft" || engine="iptables"

    c=$(ask_choice "Role de cette machine ?" \
        "Hote simple : proteger cette machine (filtrage entrant)" \
        "Routeur pare-feu 3 zones : WAN / LAN / DMZ (routage + NAT + DMZ)")
    [[ "$c" == "1" ]] && mode="hote" || mode="routeur"

    FW_SSH_PORT=$(ask_port "Port SSH a conserver ouvert (anti-verrouillage)" "${CFG_FW_SSH_PORT:-22}")
    FW_EXTRA_TCP="" ; FW_EXTRA_UDP=""
    FW_WAN_IF="" ; FW_LAN_IF="" ; FW_DMZ_IF=""
    FW_FORWARDS=()

    if [[ "$mode" == "hote" ]]; then
        FW_EXTRA_TCP=$(ask_val "Autres ports TCP a ouvrir (separes par des espaces, vide sinon)" "${CFG_FW_EXTRA_TCP:-}")
        FW_EXTRA_UDP=$(ask_val "Ports UDP a ouvrir (vide sinon)" "${CFG_FW_EXTRA_UDP:-}")
    else
        say ""
        say "  Interfaces detectees : $(list_ifaces | tr '\n' ' ')"
        FW_WAN_IF=$(ask_val "Interface WAN (vers Internet)" "${CFG_FW_WAN_IF:-$(default_iface)}")
        FW_LAN_IF=$(ask_val "Interface LAN (reseau interne)" "${CFG_FW_LAN_IF:-}")
        FW_DMZ_IF=$(ask_val "Interface DMZ (services exposes)" "${CFG_FW_DMZ_IF:-}")
        if [[ -z "$FW_LAN_IF" || -z "$FW_DMZ_IF" ]]; then
            err "Interfaces LAN/DMZ non renseignees : abandon du module."
            return 1
        fi
        fw_ask_forwards
    fi

    # Generation du jeu de regles (IPv4/inet, + IPv6 pour le moteur iptables)
    local tmp_rules tmp6_rules=""
    tmp_rules=$(new_tmp)
    if [[ "$engine" == "nft" ]]; then
        fw_generate_nft "$mode" "$tmp_rules"
    else
        fw_generate_iptables "$mode" "$tmp_rules"
        tmp6_rules=$(new_tmp)
        fw_generate_ip6tables "$mode" "$tmp6_rules"
    fi
    subtitle "Jeu de regles genere ($engine, mode $mode)"
    sed 's/^/    /' "$tmp_rules"
    if [[ -n "$tmp6_rules" ]]; then
        say ""
        subtitle "Socle IPv6 (ip6tables) genere"
        sed 's/^/    /' "$tmp6_rules"
        [[ "$mode" == "routeur" ]] && warn "Mode routeur : le FORWARD IPv6 reste permissif (a filtrer separement si vous routez de l'IPv6)."
    fi
    say ""
    if ! ask_yn "Appliquer ce jeu de regles (rollback automatique sous 60 s sans confirmation) ?" "${CFG_FW_APPLY:-n}"; then
        info "Regles non appliquees. Fichier conserve pour consultation : $tmp_rules"
        journal "Pare-feu : regles generees mais non appliquees"
        return 0
    fi

    # Prerequis et routage
    if [[ "$engine" == "nft" ]]; then
        install_pkgs nftables || return 1
    else
        install_pkgs iptables || return 1
    fi
    if [[ "$mode" == "routeur" ]]; then
        write_file /etc/sysctl.d/99-defense-reseau.conf "activation du routage IP (mode routeur)" <<'SYSCTL'
# Init-DefenseReseau : mode routeur pare-feu
net.ipv4.ip_forward = 1
# Durcissement associe (anti-usurpation, pas de redirections ICMP)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
SYSCTL
        run_cmd "Rechargement des parametres noyau" sysctl --system
    fi

    # Application avec anti-verrouillage puis persistance
    if fw_apply_with_rollback "$engine" "$tmp_rules" "$tmp6_rules"; then
        if [[ "$engine" == "nft" ]]; then
            if [[ $DRY_RUN -eq 0 ]]; then
                local nft_existed=0
                [[ -f /etc/nftables.conf ]] && nft_existed=1 && backup_file /etc/nftables.conf
                cp "$tmp_rules" /etc/nftables.conf
                [[ $nft_existed -eq 0 ]] && manifest_add "newfile|/etc/nftables.conf"
                ok "Regles persistees dans /etc/nftables.conf"
            fi
            run_cmd "Activation du service nftables au demarrage" systemctl enable nftables
            manifest_add "service|nftables"
        else
            install_pkgs iptables-persistent || warn "iptables-persistent absent : les regles ne survivront pas au redemarrage."
            if [[ $DRY_RUN -eq 0 ]]; then
                backup_file /etc/iptables/rules.v4
                mkdir -p /etc/iptables
                cp "$tmp_rules" /etc/iptables/rules.v4
                [[ -z "${BACKED_UP[/etc/iptables/rules.v4]:-}" ]] && manifest_add "newfile|/etc/iptables/rules.v4"
                ok "Regles persistees dans /etc/iptables/rules.v4"
                if [[ -n "$tmp6_rules" ]]; then
                    backup_file /etc/iptables/rules.v6
                    cp "$tmp6_rules" /etc/iptables/rules.v6
                    [[ -z "${BACKED_UP[/etc/iptables/rules.v6]:-}" ]] && manifest_add "newfile|/etc/iptables/rules.v6"
                    ok "Socle IPv6 persiste dans /etc/iptables/rules.v6"
                fi
            fi
        fi
        mark_done "parefeu"
        journal "Module 3 : pare-feu $engine ($mode) applique et persiste"
    fi
    rm -f "$tmp_rules" "$tmp6_rules"

    if ask_yn "Generer aussi le guide OPNsense (equivalent appliance) ?" "${CFG_FW_OPNSENSE_GUIDE:-o}"; then
        fw_opnsense_guide
    fi
    pause
}

#===============================================================================
# REGION 6 : MODULE 4 - IDS / IPS (Snort / Suricata)
#===============================================================================

ids_pedagogie() {
    teach <<'TXT'
  IDS : sonde qui ECOUTE le trafic (interface en mode promiscuous, TAP ou
        port mirror) et leve des ALERTES sur signatures ou anomalies.
  IPS : le meme moteur place EN COUPURE, qui BLOQUE (drop) le trafic
        malveillant. Plus protecteur, mais un faux positif coupe un flux
        legitime : on commence TOUJOURS en mode detection (IDS), on observe,
        on affine (tuning), puis seulement on passe des regles choisies en IPS.

  SNORT    : le pionnier (1998), ideal pour APPRENDRE l'ecriture de regles.
  SURICATA : moteur moderne multi-threads, parsing applicatif natif (HTTP,
             TLS, DNS...), sortie JSON (eve.json), compatible avec le format
             de regles de Snort. Recommande pour un usage reel.

  ANATOMIE D'UNE REGLE (commune aux deux moteurs) :
    action proto  source  port -> destination port (options)
    alert  tcp    any     any  -> $HOME_NET    22  (msg:"..."; sid:1000002; rev:1;)
      action : alert (IDS) / drop (IPS) / pass
      sid    : identifiant unique ; >= 1000000 pour vos regles locales
      options frequentes : content (motif), flow, threshold (seuils),
      classtype, http.user_agent / dns.query (Suricata).

  THREAT INTELLIGENCE : plutot que d'ecrire toutes les regles soi-meme, on
  s'abonne a des jeux de regles maintenus par la communaute : Emerging
  Threats Open (gratuit, via suricata-update), listes MISP, abonnements
  commerciaux (ET Pro). Le tuning (suppress/threshold) adapte ces milliers
  de regles a VOTRE reseau.
TXT
}

ids_write_local_rules_suricata() {
    write_file /etc/suricata/rules/local.rules "regles locales pedagogiques Suricata" <<'RULES'
# =====================================================================
#  Regles locales - Init-DefenseReseau (pedagogiques, adaptez !)
#  Anatomie : action proto src port -> dst port (options)
#  sid >= 1000000 reserve aux regles locales. Incrementez rev a chaque
#  modification. Testez avec : suricata -T -c /etc/suricata/suricata.yaml
# =====================================================================

# 1) Detection simple : ping entrant vers le reseau surveille
alert icmp any any -> $HOME_NET any (msg:"[LOCAL] ICMP echo-request entrant"; itype:8; classtype:misc-activity; sid:1000001; rev:1;)

# 2) Seuils : plus de 5 tentatives SSH en 60 s depuis la meme source
alert tcp any any -> $HOME_NET 22 (msg:"[LOCAL] SSH - tentatives repetees (force brute possible)"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:1000002; rev:1;)

# 3) Inspection applicative HTTP : outil en ligne de commande vers l'interne
alert http any any -> $HOME_NET any (msg:"[LOCAL] HTTP - User-Agent curl vers un serveur interne"; http.user_agent; content:"curl"; nocase; classtype:policy-violation; sid:1000003; rev:1;)

# 4) DNS : requete anormalement longue (tunneling / exfiltration possible)
alert dns $HOME_NET any -> any 53 (msg:"[LOCAL] DNS - nom de domaine anormalement long"; dns.query; bsize:>60; classtype:policy-violation; sid:1000004; rev:1;)

# 5) Conformite : protocole en clair interdit (Telnet sortant)
alert tcp $HOME_NET any -> any 23 (msg:"[LOCAL] Telnet sortant - protocole en clair interdit"; flow:to_server; classtype:policy-violation; sid:1000005; rev:1;)
RULES
}

ids_write_threshold() {
    write_file /etc/suricata/threshold.config "exemples de tuning IDS (threshold/suppress)" <<'THR'
# =====================================================================
#  Tuning IDS - Init-DefenseReseau
#  Le tuning consiste a REDUIRE LE BRUIT sans masquer les vraies alertes.
#  Demarche : 1) observer une semaine  2) identifier les alertes les plus
#  frequentes (jq ou 'sort | uniq -c' sur fast.log)  3) supprimer ou
#  limiter CIBLE PAR CIBLE, en commentant pourquoi.
#  Decommentez et adaptez les exemples ci-dessous :
# =====================================================================

# Supprimer une signature pour la sonde de supervision (faux positif connu) :
# suppress gen_id 1, sig_id 2100498, track by_src, ip 192.168.10.5

# Limiter une signature bavarde a 1 alerte / minute / source :
# threshold gen_id 1, sig_id 1000001, type limit, track by_src, count 1, seconds 60

# Ne declencher qu'a partir de 10 occurrences en 60 s (bruit de fond) :
# threshold gen_id 1, sig_id 2210045, type threshold, track by_src, count 10, seconds 60
THR
}

ids_suricata() {
    subtitle "Deploiement de Suricata"
    install_pkgs suricata || return 1
    install_pkgs suricata-update jq || true    # inclus dans suricata sur certaines versions

    local iface hn
    iface=$(ask_val "Interface a surveiller" "${CFG_IDS_IFACE:-$(default_iface)}")
    hn=$(ask_val "HOME_NET (reseaux a proteger, format [a.b.c.d/xx,...])" "${CFG_IDS_HOME_NET:-[$(iface_network "$iface" 2>/dev/null || echo 192.168.0.0/16)]}")

    local want_local=0 want_thr=0
    ask_yn "Installer les regles locales pedagogiques (local.rules : 5 regles commentees) ?" "${CFG_IDS_LOCALRULES:-o}" && want_local=1
    ask_yn "Installer les exemples de tuning (threshold.config : suppress/threshold) ?" "${CFG_IDS_THRESHOLD:-o}" && want_thr=1

    if [[ $DRY_RUN -eq 0 && -f /etc/suricata/suricata.yaml ]]; then
        backup_file /etc/suricata/suricata.yaml
        sed -i "s|HOME_NET: \"\[.*\]\"|HOME_NET: \"$hn\"|" /etc/suricata/suricata.yaml
        ok "HOME_NET defini : $hn"
        # Inclusion des regles locales aupres des regles gerees
        if [[ $want_local -eq 1 ]] && ! grep -q 'local.rules' /etc/suricata/suricata.yaml; then
            sed -i '/^rule-files:/a\  - /etc/suricata/rules/local.rules' /etc/suricata/suricata.yaml
            ok "Fichier local.rules ajoute a la configuration"
        fi
    else
        say "${C_CYA}  [SIMULATION]${C_OFF} HOME_NET=$hn dans /etc/suricata/suricata.yaml"
    fi

    [[ $want_local -eq 1 ]] && ids_write_local_rules_suricata
    [[ $want_thr -eq 1 ]] && ids_write_threshold

    if ask_yn "Telecharger les regles de threat intelligence ET Open (suricata-update, acces Internet requis) ?" "${CFG_IDS_ETOPEN:-o}"; then
        run_cmd "Mise a jour des sources de regles" suricata-update update-sources || true
        run_cmd "Activation de la source et/open (Emerging Threats Open)" suricata-update enable-source et/open || true
        run_cmd "Telechargement/compilation des regles (ET Open + locales)" suricata-update || warn "suricata-update a echoue (pas d'Internet ?) : seules les regles locales seront actives."
        info "Autres sources listables via : suricata-update list-sources (ex. abuse.ch, tgreen/hunting)"
    fi

    run_cmd "Validation de la configuration (suricata -T)" suricata -T -c /etc/suricata/suricata.yaml || {
        err "Configuration invalide : service non demarre. Consultez $LOG_FILE."
        return 1
    }
    run_cmd "Activation et demarrage du service Suricata" systemctl enable --now suricata
    manifest_add "service|suricata"

    subtitle "Tester et exploiter"
    cat <<TXT
  - Test de detection (depuis une machine du reseau surveille) :
      curl http://testmynids.org/uid/index.html
    puis :  tail -f /var/log/suricata/fast.log
  - Alertes au format JSON (pour SIEM) : /var/log/suricata/eve.json
      jq 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json
  - Top des signatures (base du tuning) :
      awk -F'\\[\\*\\*\\]' '{print \$2}' /var/log/suricata/fast.log | sort | uniq -c | sort -rn | head
TXT

    if ask_yn "Passer en mode IPS (nfqueue, trafic EN COUPURE - reserve aux configurations maitrisees) ?" "${CFG_IDS_IPS:-n}"; then
        warn "En IPS, toute erreur de regle ou panne de Suricata peut COUPER le trafic."
        if [[ -f /etc/default/suricata ]]; then
            backup_file /etc/default/suricata
            [[ $DRY_RUN -eq 0 ]] && sed -i 's/^LISTENMODE=.*/LISTENMODE=nfqueue/' /etc/default/suricata
            ok "LISTENMODE=nfqueue defini dans /etc/default/suricata"
            info "Il reste a diriger le trafic vers la file : ajoutez dans votre pare-feu nftables :"
            info '  chain transfert { ... ct state new queue num 0 bypass ... }'
            info "puis : systemctl restart suricata. Passez les regles choisies de 'alert' a 'drop'."
        else
            warn "/etc/default/suricata introuvable : configuration IPS manuelle requise."
        fi
    else
        info "Mode detection (IDS) conserve - recommande pour commencer."
    fi
    mark_done "ids"
    journal "Module 4 : Suricata deploye (iface=$iface HOME_NET=$hn)"
}

ids_snort() {
    subtitle "Deploiement de Snort (apprentissage)"
    if ! install_pkgs snort; then
        warn "Le paquet snort n'est pas disponible sur cette distribution."
        warn "Utilisez Suricata (compatible avec les regles Snort) : relancez ce module."
        return 1
    fi
    local hn
    hn=$(ask_val "HOME_NET (reseau a proteger)" "${CFG_IDS_HOME_NET:-$(iface_network "$(default_iface)" 2>/dev/null || echo 192.168.0.0/24)}")
    if [[ $DRY_RUN -eq 0 && -f /etc/snort/snort.debian.conf ]]; then
        backup_file /etc/snort/snort.debian.conf
        sed -i "s|^DEBIAN_SNORT_HOME_NET=.*|DEBIAN_SNORT_HOME_NET=\"$hn\"|" /etc/snort/snort.debian.conf
        ok "HOME_NET defini : $hn"
    fi
    if ask_yn "Installer les regles locales pedagogiques (local.rules) ?" "${CFG_IDS_LOCALRULES:-o}"; then
        write_file /etc/snort/rules/local.rules "regles locales pedagogiques Snort" <<'RULES'
# =====================================================================
#  Regles locales Snort - Init-DefenseReseau (pedagogiques)
#  Testez avec : snort -T -c /etc/snort/snort.conf
# =====================================================================

# 1) Ping entrant
alert icmp any any -> $HOME_NET any (msg:"[LOCAL] ICMP echo-request entrant"; itype:8; classtype:misc-activity; sid:1000001; rev:1;)

# 2) Force brute SSH : 5 SYN en 60 s depuis la meme source
alert tcp any any -> $HOME_NET 22 (msg:"[LOCAL] SSH - tentatives repetees"; flags:S; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:1000002; rev:1;)

# 3) Telnet sortant (protocole en clair interdit)
alert tcp $HOME_NET any -> any 23 (msg:"[LOCAL] Telnet sortant interdit"; flow:to_server; classtype:policy-violation; sid:1000005; rev:1;)
RULES
    fi
    run_cmd "Validation de la configuration (snort -T)" snort -T -c /etc/snort/snort.conf || {
        err "Configuration Snort invalide."
        return 1
    }
    run_cmd "Activation et demarrage du service Snort" systemctl enable --now snort || true
    manifest_add "service|snort"
    info "Alertes : /var/log/snort/ - testez avec un ping vers la machine surveillee."
    info "Pour aller plus loin (production), migrez vers Suricata : le format de regles est compatible."
    mark_done "ids"
    journal "Module 4 : Snort deploye (HOME_NET=$hn)"
}

module_ids() {
    title "MODULE 4 : IDS / IPS - detection et prevention d'intrusion"
    ids_pedagogie
    pause_teach
    local c
    c=$(ask_choice "Quel moteur deployer ?" \
        "Suricata (recommande : production, multi-threads, eve.json, threat intel)" \
        "Snort (apprentissage de l'ecriture de regles)" \
        "Retour")
    case "$c" in
        1) ids_suricata ;;
        2) ids_snort ;;
        3) return 0 ;;
    esac
    pause
}

#===============================================================================
# REGION 7 : MODULE 5 - PROXY DE FILTRAGE SORTANT (SQUID)
#===============================================================================

module_squid() {
    title "MODULE 5 : Proxy de filtrage sortant (Squid)"
    teach <<'TXT'
  Pourquoi un proxy sortant ? (architecture "passerelle Internet" ANSSI)
    - point de passage OBLIGE du web sortant : le pare-feu bloque le port
      80/443 direct, seuls les flux via le proxy sortent ;
    - filtrage par liste noire/blanche de domaines, types de fichiers ;
    - JOURNALISATION de qui va ou (indispensable en investigation) ;
    - rupture de flux : le poste ne parle jamais directement a Internet.
  Squid utilise des ACL (Access Control Lists) evaluees dans l'ordre :
  premiere regle http_access qui correspond gagne, et on termine toujours
  par 'http_access deny all' (moindre privilege applique au web).
TXT
    pause_teach
    ask_yn "Deployer et configurer Squid maintenant ?" "${CFG_SQUID:-o}" || return 0

    install_pkgs squid || return 1

    local lan port
    lan=$(ask_val "Reseau(x) client(s) autorise(s) (separes par des espaces)" "${CFG_SQUID_LAN:-$(iface_network "$(default_iface)" 2>/dev/null || echo 192.168.10.0/24)}")
    port=$(ask_val "Port d'ecoute du proxy" "${CFG_SQUID_PORT:-3128}")

    write_file /etc/squid/domaines-bloques.acl "liste noire de domaines (exemples)" <<'ACL'
# Domaines bloques - un par ligne, le point initial couvre les sous-domaines.
# Alimentez cette liste avec vos categories interdites ou des listes
# publiques reconnues (ex. blocklists universitaires, CERT-FR).
.exemple-bloque.fr
.jeux-en-ligne-exemple.com
.malware-exemple.net
ACL

    local acl_lines="" n
    for n in $lan; do
        acl_lines+="acl reseau_local src $n"$'\n'
    done

    write_file /etc/squid/squid.conf "configuration Squid (filtrage sortant, deny all final)" <<SQUIDCONF
# =====================================================================
#  Squid - proxy de filtrage sortant - genere par $SCRIPT_NAME
#  Principe : ACL nommees, puis regles http_access evaluees DANS L'ORDRE,
#  et refus de tout le reste (moindre privilege).
# =====================================================================
http_port $port

# --- Definitions (ACL) ---
${acl_lines}acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 443         # https
acl Safe_ports port 21          # ftp
acl Safe_ports port 1025-65535  # ports hauts (applicatifs)
acl CONNECT method CONNECT
acl domaines_bloques dstdomain "/etc/squid/domaines-bloques.acl"

# --- Politique (l'ordre compte, premiere correspondance gagne) ---
http_access deny !Safe_ports                # ports exotiques interdits
http_access deny CONNECT !SSL_ports         # CONNECT reserve au HTTPS
http_access deny domaines_bloques           # liste noire
http_access allow localhost manager         # supervision locale
http_access deny manager
http_access allow reseau_local              # clients autorises
http_access allow localhost
http_access deny all                        # TOUT LE RESTE EST REFUSE

# --- Journalisation et divers ---
access_log /var/log/squid/access.log squid
cache deny all                              # proxy de filtrage : pas de cache
coredump_dir /var/spool/squid
# Masquer la version dans les pages d'erreur
httpd_suppress_version_string on
SQUIDCONF

    run_cmd "Validation de la configuration (squid -k parse)" squid -k parse || {
        err "Configuration Squid invalide : service non redemarre."
        return 1
    }
    run_cmd "Redemarrage de Squid" systemctl restart squid
    run_cmd "Activation au demarrage" systemctl enable squid
    manifest_add "service|squid"

    subtitle "Tester"
    cat <<TXT
  Depuis un poste client :
    curl -x http://IP_DU_PROXY:$port https://www.anssi.fr -I     # doit passer
    curl -x http://IP_DU_PROXY:$port http://exemple-bloque.fr    # doit etre refuse (403)
  Journal : tail -f /var/log/squid/access.log
  Pour rendre le proxy OBLIGATOIRE : bloquez 80/443 sortants au pare-feu
  (module 3) sauf depuis l'IP du proxy lui-meme.
TXT
    mark_done "proxy"
    journal "Module 5 : Squid configure (port $port, reseaux : $lan)"
    pause
}

#===============================================================================
# REGION 8 : MODULE 6 - REVERSE PROXY (NGINX / HAPROXY)
#===============================================================================

revproxy_selfsigned_cert() {
    # $1 = CN ; genere un certificat auto-signe de lab dans /etc/ssl/defense-reseau/
    local cn="$1" dir="/etc/ssl/defense-reseau"
    CERT_CRT="$dir/$cn.crt"; CERT_KEY="$dir/$cn.key"
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} Generation d'un certificat auto-signe pour $cn dans $dir"
        return 0
    fi
    mkdir -p "$dir"; manifest_add "dir|$dir"
    if [[ -f "$CERT_CRT" ]]; then
        info "Certificat deja present : $CERT_CRT"
        return 0
    fi
    # SAN = CN : les navigateurs recents exigent un subjectAltName
    run_cmd "Generation d'un certificat auto-signe (lab) pour $cn" \
        openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
            -keyout "$CERT_KEY" -out "$CERT_CRT" -subj "/CN=$cn" \
            -addext "subjectAltName=DNS:$cn" || return 1
    chmod 600 "$CERT_KEY"
    manifest_add "newfile|$CERT_CRT"
    manifest_add "newfile|$CERT_KEY"
    warn "Certificat AUTO-SIGNE (maquette). En production : certificat valide (Let's Encrypt/PKI interne)."
}

# revproxy_obtain_cert <cn> : definit CERT_CRT / CERT_KEY et CERT_MODE selon la
# source choisie (certificat existant, Let's Encrypt, ou auto-signe de lab).
revproxy_obtain_cert() {
    local cn="$1" src
    CERT_MODE="selfsigned"
    if [[ $UNATTENDED -eq 1 ]]; then
        src="${CFG_RP_CERT_MODE:-selfsigned}"
    else
        local ch
        ch=$(ask_choice "Source du certificat TLS pour $cn ?" \
            "Certificat existant (PKI interne / deja emis) - RECOMMANDE en production" \
            "Let's Encrypt via certbot (domaine public + port 80 joignables)" \
            "Auto-signe (maquette / lab)")
        case "$ch" in 1) src="existing" ;; 2) src="letsencrypt" ;; *) src="selfsigned" ;; esac
    fi

    case "$src" in
        existing)
            local crt key cmod kmod
            crt=$(ask_val "Chemin du certificat (fullchain .crt/.pem)" "${CFG_RP_CERT_CRT:-}")
            key=$(ask_val "Chemin de la cle privee (.key)" "${CFG_RP_CERT_KEY:-}")
            if [[ $DRY_RUN -eq 1 ]]; then
                say "${C_CYA}  [SIMULATION]${C_OFF} Utilisation du certificat existant $crt / $key"
                CERT_CRT="$crt"; CERT_KEY="$key"; CERT_MODE="existing"; return 0
            fi
            if [[ ! -s "$crt" || ! -s "$key" ]]; then
                err "Certificat ou cle introuvable : bascule sur un certificat auto-signe de lab."
                revproxy_selfsigned_cert "$cn"; return $?
            fi
            # La cle correspond-elle au certificat ? (compare les modules, RSA ou EC)
            cmod=$(openssl x509 -noout -modulus -in "$crt" 2>/dev/null | openssl md5 2>/dev/null)
            kmod=$(openssl rsa  -noout -modulus -in "$key" 2>/dev/null | openssl md5 2>/dev/null)
            if [[ -n "$cmod" && -n "$kmod" && "$cmod" != "$kmod" ]]; then
                warn "La cle privee ne semble PAS correspondre au certificat : verifiez avant mise en service."
            fi
            CERT_CRT="$crt"; CERT_KEY="$key"; CERT_MODE="existing"
            ok "Certificat existant utilise : $crt"
            ;;
        letsencrypt)
            # Certificat temporaire auto-signe pour que la config passe la validation ;
            # certbot le remplacera ensuite (voir revproxy_nginx).
            CERT_MODE="letsencrypt"
            revproxy_selfsigned_cert "$cn"
            ;;
        *)
            revproxy_selfsigned_cert "$cn"
            ;;
    esac
}

revproxy_nginx() {
    install_pkgs nginx || return 1
    local name backend
    name=$(ask_val "Nom de domaine servi (server_name)" "${CFG_RP_NAME:-app.exemple.local}")
    backend=$(ask_val "Backend a proteger (URL interne, ex: http://192.168.20.10:8080)" "${CFG_RP_BACKEND:-http://192.168.20.10:8080}")
    revproxy_obtain_cert "$name" || return 1

    write_file "/etc/nginx/sites-available/reverse-proxy-$name.conf" "reverse proxy Nginx ($name)" <<NGINX
# Reverse proxy - genere par $SCRIPT_NAME
# Roles : terminaison TLS, en-tetes de securite, masquage du backend.
server {
    listen 80;
    server_name $name;
    return 301 https://\$host\$request_uri;      # tout en HTTPS
}

server {
    listen 443 ssl;
    server_name $name;

    ssl_certificate     $CERT_CRT;
    ssl_certificate_key $CERT_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;         # cf. recommandations TLS ANSSI
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;

    # En-tetes de securite
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    server_tokens off;

    # Limitation simple du nombre de connexions par IP
    limit_conn par_ip 20;

    location / {
        proxy_pass $backend;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }
}
NGINX
    write_file "/etc/nginx/conf.d/defense-reseau-limites.conf" "zone de limitation de connexions" <<'NGINX2'
# Zone partagee pour limit_conn (reverse proxy Init-DefenseReseau)
limit_conn_zone $binary_remote_addr zone=par_ip:10m;
NGINX2
    if [[ $DRY_RUN -eq 0 ]]; then
        ln -sf "/etc/nginx/sites-available/reverse-proxy-$name.conf" "/etc/nginx/sites-enabled/reverse-proxy-$name.conf"
        manifest_add "newfile|/etc/nginx/sites-enabled/reverse-proxy-$name.conf"
    fi
    run_cmd "Validation de la configuration (nginx -t)" nginx -t || {
        err "Configuration Nginx invalide : rechargement annule."
        return 1
    }
    run_cmd "Rechargement de Nginx" systemctl reload nginx
    run_cmd "Activation au demarrage" systemctl enable nginx
    manifest_add "service|nginx"

    # Let's Encrypt : certbot --nginx obtient un vrai certificat et le substitue a
    # l'auto-signe temporaire, puis programme le renouvellement automatique (timer).
    if [[ "${CERT_MODE:-}" == "letsencrypt" && $DRY_RUN -eq 0 ]]; then
        if install_pkgs certbot python3-certbot-nginx; then
            local email
            local -a certbot_args=(--nginx -d "$name" --non-interactive --agree-tos --redirect)
            email=$(ask_val "E-mail d'enregistrement Let's Encrypt (avis d'expiration, vide pour aucun)" "${CFG_RP_LE_EMAIL:-}")
            if [[ -n "$email" ]]; then
                certbot_args+=(--email "$email")
            else
                certbot_args+=(--register-unsafely-without-email)
            fi
            if run_cmd "Obtention du certificat Let's Encrypt pour $name" certbot "${certbot_args[@]}"; then
                ok "Certificat Let's Encrypt installe ; renouvellement automatique via le timer certbot."
            else
                warn "certbot a echoue (domaine non resolu ou port 80 injoignable ?) : l'auto-signe temporaire reste en place."
            fi
        fi
    fi
    info "Test : curl -k https://$name/ --resolve $name:443:IP_DU_PROXY"
    journal "Module 6 : reverse proxy Nginx configure ($name -> $backend, cert=${CERT_MODE:-selfsigned})"
}

revproxy_haproxy() {
    install_pkgs haproxy || return 1
    local name backend pem="/etc/haproxy/certs/reverse.pem"
    name=$(ask_val "Nom de domaine servi" "${CFG_RP_NAME:-app.exemple.local}")
    backend=$(ask_val "Backend (IP:port, ex: 192.168.20.10:8080)" "${CFG_RP_BACKEND_HA:-192.168.20.10:8080}")
    revproxy_obtain_cert "$name" || return 1
    if [[ "${CERT_MODE:-}" == "letsencrypt" ]]; then
        warn "Let's Encrypt automatique n'est cable que pour Nginx : HAProxy utilise ici l'auto-signe temporaire."
        info "Pour un vrai certificat : 'certbot certonly --standalone -d $name' (HAProxy arrete sur :80), puis"
        info "  cat /etc/letsencrypt/live/$name/fullchain.pem /etc/letsencrypt/live/$name/privkey.pem > $pem && systemctl reload haproxy"
    fi
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p /etc/haproxy/certs
        cat "$CERT_CRT" "$CERT_KEY" > "$pem"
        chmod 600 "$pem"
        manifest_add "newfile|$pem"
    fi
    backup_file /etc/haproxy/haproxy.cfg
    if [[ $DRY_RUN -eq 0 ]] && ! grep -q "fe_defense_reseau" /etc/haproxy/haproxy.cfg; then
        cat >> /etc/haproxy/haproxy.cfg <<HAP

# --- Ajoute par $SCRIPT_NAME : reverse proxy avec TLS et en-tetes ---
frontend fe_defense_reseau
    bind *:80
    bind *:443 ssl crt $pem
    http-request redirect scheme https unless { ssl_fc }
    http-response set-header Strict-Transport-Security "max-age=63072000"
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    default_backend be_defense_reseau

backend be_defense_reseau
    option httpchk GET /
    server app1 $backend check
HAP
        ok "Blocs frontend/backend ajoutes a /etc/haproxy/haproxy.cfg"
    else
        [[ $DRY_RUN -eq 1 ]] && say "${C_CYA}  [SIMULATION]${C_OFF} Ajout frontend/backend TLS a haproxy.cfg" \
                             || info "Blocs deja presents dans haproxy.cfg : inchanges."
    fi
    run_cmd "Validation de la configuration (haproxy -c)" haproxy -c -f /etc/haproxy/haproxy.cfg || {
        err "Configuration HAProxy invalide : service non redemarre."
        return 1
    }
    run_cmd "Redemarrage de HAProxy" systemctl restart haproxy
    run_cmd "Activation au demarrage" systemctl enable haproxy
    manifest_add "service|haproxy"
    info "Sante du backend : option httpchk = HAProxy retire le serveur s'il ne repond plus."
    journal "Module 6 : reverse proxy HAProxy configure ($name -> $backend)"
}

module_revproxy() {
    title "MODULE 6 : Reverse proxy (Nginx / HAProxy)"
    teach <<'TXT'
  Le reverse proxy est la FACADE unique de vos services web (typiquement en
  DMZ, devant les serveurs applicatifs) :
    - terminaison TLS centralisee (un seul endroit ou gerer certificats et
      protocoles - cf. recommandations TLS de l'ANSSI) ;
    - masquage des serveurs internes (l'attaquant ne voit que le proxy) ;
    - en-tetes de securite (HSTS, X-Frame-Options, nosniff...) ;
    - repartition de charge et controle de sante des backends (HAProxy) ;
    - point d'ancrage naturel pour un futur WAF (ModSecurity + OWASP CRS).
  NGINX  : simple et polyvalent (serveur web + reverse proxy).
  HAPROXY: specialiste de la repartition de charge et de la haute dispo.
TXT
    pause_teach
    local c
    c=$(ask_choice "Quel reverse proxy deployer ?" \
        "Nginx (recommande pour debuter : un fichier de site dedie)" \
        "HAProxy (repartition de charge, controles de sante)" \
        "Retour")
    case "$c" in
        1) revproxy_nginx && mark_done "revproxy" ;;
        2) revproxy_haproxy && mark_done "revproxy" ;;
        3) return 0 ;;
    esac
    pause
}

#===============================================================================
# REGION 9 : MODULE 7 - BASTION SSH (ANSSI)
#===============================================================================

module_bastion() {
    title "MODULE 7 : Bastion SSH - securiser les acces administrateur"
    teach <<'TXT'
  Le bastion est LE point d'entree unique de l'administration : les
  administrateurs s'y connectent, puis rebondissent vers les serveurs
  internes. Interets : une seule porte a defendre et a JOURNALISER, MFA et
  restrictions concentres, plus aucun serveur interne expose.

     Admin --(SSH cle + MFA)--> [BASTION] --(ProxyJump)--> serveurs internes

  Ce module applique le guide ANSSI "Recommandations pour un usage securise
  d'(Open)SSH" : authentification par CLES uniquement, root interdit,
  algorithmes de chiffrement recents, groupe d'acces dedie (AllowGroups),
  journalisation renforcee, banniere legale, fail2ban.

  GARDE-FOU : la desactivation des mots de passe n'est proposee que si une
  cle publique est deja installee, et la configuration est validee
  (sshd -t) avant redemarrage. Votre session SSH actuelle reste ouverte.
TXT
    pause_teach
    ask_yn "Durcir le service SSH de cette machine en bastion ?" "${CFG_BASTION:-o}" || return 0

    local grp adminuser sshport
    grp=$(ask_val "Groupe autorise a se connecter (AllowGroups)" "${CFG_BASTION_GROUP:-adminssh}")
    adminuser=$(ask_val "Utilisateur admin a placer dans ce groupe" "${CFG_BASTION_USER:-${SUDO_USER:-$USER}}")
    sshport=$(ask_port "Port d'ecoute SSH" "${CFG_BASTION_PORT:-22}")

    if ! getent group "$grp" >/dev/null 2>&1; then
        run_cmd "Creation du groupe $grp" groupadd "$grp" && manifest_add "group|$grp"
    else
        info "Groupe deja present : $grp"
    fi
    if id "$adminuser" >/dev/null 2>&1; then
        run_cmd "Ajout de $adminuser au groupe $grp" usermod -aG "$grp" "$adminuser"
    else
        warn "Utilisateur $adminuser inexistant : creez-le puis ajoutez-le a $grp avant de vous deconnecter !"
    fi

    # Garde-fou : une cle publique doit exister avant de couper les mots de passe
    local pwauth="yes" home keyfile
    home=$(getent passwd "$adminuser" | cut -d: -f6)
    keyfile="$home/.ssh/authorized_keys"
    if [[ -s "$keyfile" ]]; then
        ok "Cle(s) publique(s) presente(s) pour $adminuser ($keyfile)"
        if ask_yn "Desactiver l'authentification par mot de passe (cles uniquement, recommande) ?" "${CFG_BASTION_NOPASS:-o}"; then
            pwauth="no"
        fi
    else
        warn "AUCUNE cle publique pour $adminuser : l'authentification par mot de passe est CONSERVEE."
        warn "Installez une cle (ssh-copy-id $adminuser@bastion, cle ed25519 recommandee) puis relancez ce module."
    fi

    write_file /etc/issue.net "banniere legale de connexion" <<'BANNER'
*******************************************************************
*  ACCES RESERVE - Systeme d'administration                       *
*  Toute connexion est journalisee. Tout acces non autorise       *
*  est interdit et passible de poursuites (art. 323-1 et suivants *
*  du Code penal).                                                *
*******************************************************************
BANNER

    write_file /etc/ssh/sshd_config.d/50-bastion-anssi.conf "durcissement sshd (guide ANSSI OpenSSH)" <<SSHD
# =====================================================================
#  Bastion SSH - durcissement selon le guide ANSSI (Open)SSH
#  Genere par $SCRIPT_NAME. Valide par 'sshd -t' avant application.
# =====================================================================
Port $sshport

# Authentification : cles uniquement, root interdit
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication $pwauth
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
AllowGroups $grp

# Cryptographie (algorithmes recents uniquement)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Reduction de surface et role de bastion
X11Forwarding no
AllowAgentForwarding yes
AllowTcpForwarding yes      # necessaire au rebond ProxyJump vers l'interne
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2

# Journalisation renforcee et banniere legale
LogLevel VERBOSE
Banner /etc/issue.net
SSHD

    # Validation avant tout redemarrage (anti-verrouillage)
    if [[ $DRY_RUN -eq 0 ]]; then
        if sshd -t 2>>"$LOG_FILE"; then
            ok "Configuration sshd valide (sshd -t)."
            run_cmd "Redemarrage du service SSH" systemctl restart ssh || run_cmd "Redemarrage du service sshd" systemctl restart sshd
            warn "GARDEZ cette session ouverte et TESTEZ une nouvelle connexion dans un autre terminal."
        else
            err "sshd -t a echoue : suppression du fichier de durcissement, service inchange."
            rm -f /etc/ssh/sshd_config.d/50-bastion-anssi.conf
            return 1
        fi
    fi

    if ask_yn "Installer fail2ban (bannissement automatique des sources en echec) ?" "${CFG_BASTION_FAIL2BAN:-o}"; then
        install_pkgs fail2ban && {
            write_file /etc/fail2ban/jail.local "prison fail2ban pour sshd" <<F2B
# Genere par $SCRIPT_NAME
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
# backend systemd : lit le journal (journald). Indispensable sur les distributions
# recentes (Ubuntu 24.04...) ou /var/log/auth.log n'existe plus par defaut.
backend = systemd
port    = $sshport
F2B
            run_cmd "Redemarrage de fail2ban" systemctl restart fail2ban
            run_cmd "Activation au demarrage" systemctl enable fail2ban
            manifest_add "service|fail2ban"
        }
    fi

    local dir="${CFG_REPORT_DIR:-$REPORT_DIR_DEFAULT}"
    [[ $DRY_RUN -eq 0 ]] && mkdir -p "$dir"
    write_file "$dir/guide-bastion-utilisateurs.md" "guide d'usage du bastion (ProxyJump)" <<GUIDE
# Utiliser le bastion SSH

## Cote administrateur (poste client)
1. Generer une cle moderne (une par personne, protegee par phrase secrete) :
       ssh-keygen -t ed25519 -C "prenom.nom"
2. La deposer sur le bastion :
       ssh-copy-id -p $sshport $adminuser@BASTION
3. Configurer le rebond dans ~/.ssh/config :

       Host bastion
           HostName IP_DU_BASTION
           Port $sshport
           User $adminuser

       Host srv-*.interne
           ProxyJump bastion
           User admin

   Puis simplement :  ssh srv-web1.interne
   (le flux est chiffre de bout en bout, le bastion ne fait que relayer)

## Cote serveurs internes
- N'acceptez les connexions SSH QUE depuis l'IP du bastion (pare-feu,
  module 3), et le meme durcissement sshd s'applique.

## Journalisation
- Connexions : journalctl -u ssh (LogLevel VERBOSE : empreinte de la cle
  utilisee = QUI s'est connecte, meme sur un compte partage).
- Bannissements : fail2ban-client status sshd
- Pour l'enregistrement de session complet (video/texte), regardez des
  bastions specialises : Teleport, Apache Guacamole, tlog.
GUIDE

    mark_done "bastion"
    journal "Module 7 : bastion SSH durci (groupe=$grp port=$sshport cles_uniquement=$([[ $pwauth == no ]] && echo oui || echo non))"
    pause
}

#===============================================================================
# REGION 10 : MODULE 8 - MOINDRE PRIVILEGE
#===============================================================================

module_privileges() {
    title "MODULE 8 : Moindre privilege et defense en profondeur systeme"
    teach <<'TXT'
  Le moindre privilege au niveau systeme complete les barrieres reseau :
    - sudo GRANULAIRE : deleguer une commande precise, pas 'ALL' ;
    - umask restrictif : les nouveaux fichiers ne sont pas lisibles de tous ;
    - reduire la surface : desactiver les services inutiles ;
    - politique de mots de passe robuste (pwquality, ANSSI : longueur > tout).
TXT
    pause_teach

    # --- 8.1 : audit sudoers ---
    subtitle "8.1 Audit des delegations sudo existantes"
    local risky
    risky=$(grep -rhE '^[^#].*(NOPASSWD|ALL[[:space:]]*=[[:space:]]*\(ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^%sudo\|^root\|^%admin\|^Defaults' || true)
    if [[ -n "$risky" ]]; then
        warn "Delegations larges ou sans mot de passe detectees :"
        printf '%s\n' "$risky" | sed 's/^/      /'
    else
        ok "Aucune delegation manifestement dangereuse en dehors des groupes standard."
    fi

    # --- 8.2 : exemple de sudoers granulaire ---
    if ask_yn "Installer un exemple de delegation sudo GRANULAIRE (fichier commente, groupe dedie) ?" "${CFG_PRIV_SUDOERS:-o}"; then
        local dgrp
        dgrp=$(ask_val "Nom du groupe delegue (ex: exploitants)" "${CFG_PRIV_GROUP:-exploitants}")
        if ! getent group "$dgrp" >/dev/null 2>&1; then
            run_cmd "Creation du groupe $dgrp" groupadd "$dgrp" && manifest_add "group|$dgrp"
        fi
        local tmpsudo
        tmpsudo=$(new_tmp)
        cat > "$tmpsudo" <<SUDOERS
# =====================================================================
#  Delegation sudo GRANULAIRE - $SCRIPT_NAME (moindre privilege)
#  Principe : un alias de commandes PRECIS par role, jamais 'ALL'.
#  Validez toujours avec : visudo -cf <fichier>
# =====================================================================

# Le groupe $dgrp peut UNIQUEMENT gerer les services et lire les journaux
Cmnd_Alias EXPLOITATION = /usr/bin/systemctl status *, \\
                          /usr/bin/systemctl restart nginx, \\
                          /usr/bin/systemctl restart haproxy, \\
                          /usr/bin/systemctl restart squid, \\
                          /usr/bin/systemctl restart suricata, \\
                          /usr/bin/journalctl *

%$dgrp ALL=(root) EXPLOITATION

# Contre-exemples a NE PAS reproduire :
#   utilisateur ALL=(ALL) NOPASSWD: ALL     <- equivaut a donner root
#   %groupe ALL=(ALL) /usr/bin/vim          <- vim permet d'ouvrir un shell root
SUDOERS
        if [[ $DRY_RUN -eq 1 ]]; then
            say "${C_CYA}  [SIMULATION]${C_OFF} Ecriture de /etc/sudoers.d/60-moindre-privilege (apres visudo -cf)"
        elif visudo -cf "$tmpsudo" >>"$LOG_FILE" 2>&1; then
            install -m 0440 "$tmpsudo" /etc/sudoers.d/60-moindre-privilege
            manifest_add "newfile|/etc/sudoers.d/60-moindre-privilege"
            ok "Delegation installee : /etc/sudoers.d/60-moindre-privilege (syntaxe validee par visudo)"
        else
            err "visudo -cf a rejete le fichier : rien n'a ete installe."
        fi
        rm -f "$tmpsudo"
    fi

    # --- 8.3 : umask ---
    if ask_yn "Appliquer un umask restrictif 027 par defaut (/etc/login.defs) ?" "${CFG_PRIV_UMASK:-o}"; then
        if [[ $DRY_RUN -eq 0 && -f /etc/login.defs ]]; then
            backup_file /etc/login.defs
            sed -i 's/^UMASK[[:space:]].*/UMASK\t\t027/' /etc/login.defs
            ok "UMASK 027 defini dans /etc/login.defs (effet aux prochaines sessions)"
        else
            say "${C_CYA}  [SIMULATION]${C_OFF} UMASK 027 dans /etc/login.defs"
        fi
        journal "Module 8 : umask 027 applique"
    fi

    # --- 8.4 : politique de mots de passe ---
    if ask_yn "Installer une politique de mots de passe robuste (libpam-pwquality, longueur 12) ?" "${CFG_PRIV_PWQUALITY:-o}"; then
        install_pkgs libpam-pwquality && \
        write_file /etc/security/pwquality.conf "politique de qualite des mots de passe" <<'PWQ'
# Politique de mots de passe - Init-DefenseReseau
# Position ANSSI : la LONGUEUR prime sur la complexite imposee.
minlen = 12
minclass = 3
maxrepeat = 3
usercheck = 1
enforce_for_root
PWQ
    fi

    # --- 8.5 : services inutiles ---
    subtitle "8.5 Reduction de la surface d'attaque"
    say "  Ports en ecoute actuellement :"
    ss -tulnp 2>/dev/null | sed 's/^/    /' | head -25
    say ""
    say "  Services actives au demarrage (extraits) :"
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null | sed 's/^/    /' | head -20
    if [[ $UNATTENDED -eq 0 ]]; then
        local svc
        while true; do
            printf '%s' "  Service a desactiver (vide pour terminer) : "
            read -r svc
            [[ -z "$svc" ]] && break
            if systemctl list-unit-files "$svc.service" --no-legend 2>/dev/null | grep -q .; then
                ask_yn "Confirmer la desactivation de $svc ?" "n" && \
                    run_cmd "Desactivation de $svc" systemctl disable --now "$svc"
            else
                err "Service inconnu : $svc"
            fi
        done
    fi
    info "Chaque service en moins = une porte en moins (Guide d'hygiene ANSSI : n'installer que le necessaire)."
    mark_done "privileges"
    journal "Module 8 : moindre privilege applique"
    pause
}

#===============================================================================
# REGION 11 : MODULE 9 - AUDIT D'HYGIENE (ANSSI, lecture seule)
#===============================================================================

AUDIT_OK=0; AUDIT_KO=0
declare -a AUDIT_FIXES=()

audit_check() {
    # audit_check "statut(ok|ko)" "libelle" "detail" "recommandation" ["id_correction"]
    # Si un id_correction est fourni sur un constat 'ko', la correction sera
    # proposee individuellement en fin d'audit (appliquer ou ignorer).
    local st="$1" lbl="$2" det="$3" rec="$4" fix="${5:-}"
    printf '%s\t%s\t%s\t%s\n' "$st" "$lbl" "$det" "$rec" >> "$AUDIT_TSV"
    if [[ "$st" == "ok" ]]; then
        AUDIT_OK=$((AUDIT_OK+1)); ok "$lbl${det:+ - $det}"
    else
        AUDIT_KO=$((AUDIT_KO+1)); warn "$lbl${det:+ - $det}"
        [[ -n "$rec" ]] && say "       -> $rec"
        [[ -n "$fix" ]] && AUDIT_FIXES+=("$fix|$lbl")
    fi
}

# sysctl_fix cle valeur : applique immediatement ET persiste le durcissement
sysctl_fix() {
    local key="$1" val="$2" f="/etc/sysctl.d/98-defense-reseau-audit.conf"
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} sysctl $key=$val (persiste dans $f)"
        journal "SIMULATION : sysctl $key=$val"
        return 0
    fi
    if [[ ! -f "$f" ]]; then
        printf '# Durcissement noyau - corrections du module 9 (%s)\n' "$SCRIPT_NAME" > "$f"
        manifest_add "newfile|$f"
    fi
    if grep -q "^$key" "$f"; then
        sed -i "s|^$key.*|$key = $val|" "$f"
    else
        printf '%s = %s\n' "$key" "$val" >> "$f"
    fi
    run_cmd "Application de $key = $val" sysctl -w "$key=$val"
}

# apply_fix id : execute la correction reelle associee a un constat d'audit
apply_fix() {
    local id="$1" u f
    case "$id" in
        maj)
            run_cmd "Mise a jour de l'index des paquets" env DEBIAN_FRONTEND=noninteractive apt-get update -qq
            run_cmd "Installation des mises a jour" env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
            ;;
        unattended)
            install_pkgs unattended-upgrades && \
            write_file /etc/apt/apt.conf.d/20auto-upgrades "activation des mises a jour automatiques" <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
            ;;
        fail2ban)
            install_pkgs fail2ban && {
                run_cmd "Activation de fail2ban" systemctl enable --now fail2ban
                manifest_add "service|fail2ban"
            }
            ;;
        emptypw)
            for u in $(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null); do
                if ask_yn "Verrouiller le compte sans mot de passe '$u' ?" "o"; then
                    run_cmd "Verrouillage du compte $u" passwd -l "$u"
                fi
            done
            ;;
        shadowperm)
            run_cmd "Permissions 640 sur /etc/shadow" chmod 640 /etc/shadow
            run_cmd "Proprietaire root:shadow sur /etc/shadow" chown root:shadow /etc/shadow
            ;;
        ww_etc)
            while IFS= read -r f; do
                run_cmd "Retrait du droit d'ecriture 'autres' : $f" chmod o-w "$f"
            done < <(find /etc -xdev -type f -perm -0002 2>/dev/null)
            ;;
        sysctl_fwd)        sysctl_fix net.ipv4.ip_forward 0 ;;
        sysctl_redirects)  sysctl_fix net.ipv4.conf.all.accept_redirects 0 ;;
        sysctl_syncookies) sysctl_fix net.ipv4.tcp_syncookies 1 ;;
        rsyslog)
            install_pkgs rsyslog && {
                run_cmd "Activation de rsyslog" systemctl enable --now rsyslog
                manifest_add "service|rsyslog"
            }
            ;;
        auditd)
            install_pkgs auditd && {
                run_cmd "Activation d'auditd" systemctl enable --now auditd
                manifest_add "service|auditd"
            }
            ;;
        parefeu)    info "Ouverture du module 3 (pare-feu)..." ; module_firewall ;;
        bastion)    info "Ouverture du module 7 (bastion SSH)..." ; module_bastion ;;
        ids)        info "Ouverture du module 4 (IDS/IPS)..." ; module_ids ;;
        privileges) info "Ouverture du module 8 (moindre privilege)..." ; module_privileges ;;
        *) warn "Correction inconnue : $id" ;;
    esac
}

module_audit() {
    title "MODULE 9 : Audit d'hygiene (lecture seule, referentiels ANSSI)"
    say "  Verifications inspirees du Guide d'hygiene informatique de l'ANSSI"
    say "  (maintenir le systeme a jour, cloisonner, durcir, journaliser)."
    say "  L'audit est en LECTURE SEULE ; a la fin, chaque point non conforme"
    say "  corrigeable vous est propose individuellement : appliquer ou ignorer."
    say ""
    : > "$AUDIT_TSV"; AUDIT_OK=0; AUDIT_KO=0; AUDIT_FIXES=()

    # 1. Mises a jour
    local nb
    if command -v apt-get >/dev/null 2>&1; then
        nb=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true)
        if [[ "${nb:-0}" -eq 0 ]]; then
            audit_check ok "Mises a jour : systeme a jour" "" ""
        else
            audit_check ko "Mises a jour : $nb paquet(s) en attente" "" "apt update && apt upgrade ; envisagez unattended-upgrades (theme ANSSI : maintenir a jour)." maj
        fi
        if dpkg -s unattended-upgrades >/dev/null 2>&1; then
            audit_check ok "Mises a jour automatiques (unattended-upgrades) presentes" "" ""
        else
            audit_check ko "Pas de mises a jour automatiques" "" "apt install unattended-upgrades" unattended
        fi
    fi

    # 2. Pare-feu actif
    if { command -v nft >/dev/null && [[ -n "$(nft list ruleset 2>/dev/null)" ]]; } || \
       { command -v iptables >/dev/null && [[ "$(iptables -S 2>/dev/null | wc -l)" -gt 3 ]]; }; then
        audit_check ok "Pare-feu local : des regles sont chargees" "" ""
    else
        audit_check ko "Pare-feu local : aucune regle active" "" "Module 3 de ce script (politique par defaut DROP)." parefeu
    fi

    # 3. SSH
    if command -v sshd >/dev/null 2>&1; then
        local eff
        eff=$(sshd -T 2>/dev/null || true)
        if printf '%s' "$eff" | grep -qi '^permitrootlogin no'; then
            audit_check ok "SSH : connexion root interdite" "" ""
        else
            audit_check ko "SSH : connexion root autorisee" "" "PermitRootLogin no (guide ANSSI OpenSSH, module 7)." bastion
        fi
        if printf '%s' "$eff" | grep -qi '^passwordauthentication no'; then
            audit_check ok "SSH : authentification par cles uniquement" "" ""
        else
            audit_check ko "SSH : mots de passe acceptes" "" "Deployez des cles puis PasswordAuthentication no (module 7)." bastion
        fi
        if [[ -f /etc/ssh/sshd_config.d/50-bastion-anssi.conf ]]; then
            audit_check ok "SSH : profil de durcissement ANSSI present" "" ""
        else
            audit_check ko "SSH : algorithmes par defaut (non restreints)" "" "Restreignez Kex/Ciphers/MACs (module 7)." bastion
        fi
    fi

    # 4. fail2ban
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        audit_check ok "fail2ban actif" "" ""
    else
        audit_check ko "fail2ban absent ou inactif" "" "Protection contre la force brute (module 7)." fail2ban
    fi

    # 5. IDS
    if systemctl is-active suricata >/dev/null 2>&1 || systemctl is-active snort >/dev/null 2>&1; then
        audit_check ok "IDS actif (Suricata/Snort)" "" ""
    else
        audit_check ko "Aucun IDS actif" "" "Detection d'intrusion : module 4." ids
    fi

    # 6. Comptes
    local uid0 vides
    uid0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
    if [[ -z "$uid0" ]]; then
        audit_check ok "Comptes : seul root a l'UID 0" "" ""
    else
        audit_check ko "Comptes avec UID 0 en plus de root : $uid0" "" "A supprimer ou corriger immediatement."
    fi
    vides=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
    if [[ -z "$vides" ]]; then
        audit_check ok "Comptes : aucun mot de passe vide" "" ""
    else
        audit_check ko "Comptes SANS mot de passe : $vides" "" "passwd -l <compte> ou definir un mot de passe." emptypw
    fi

    # 7. sudo NOPASSWD
    if grep -rqE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        audit_check ko "sudo : delegations NOPASSWD presentes" "" "Limitez a des commandes precises (module 8)." privileges
    else
        audit_check ok "sudo : pas de NOPASSWD" "" ""
    fi

    # 8. Permissions sensibles
    local perm
    perm=$(stat -c '%a' /etc/shadow 2>/dev/null)
    if [[ "$perm" =~ ^(600|640|000)$ ]]; then
        audit_check ok "/etc/shadow protege ($perm)" "" ""
    else
        audit_check ko "/etc/shadow : permissions $perm" "" "chmod 640 /etc/shadow ; chown root:shadow." shadowperm
    fi
    local ww
    ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -5 | tr '\n' ' ')
    if [[ -z "$ww" ]]; then
        audit_check ok "/etc : aucun fichier modifiable par tous" "" ""
    else
        audit_check ko "/etc : fichiers world-writable : $ww" "" "chmod o-w sur ces fichiers." ww_etc
    fi

    # 9. Parametres noyau reseau
    local fwd rd
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if is_done "parefeu" && [[ "$fwd" == "1" ]]; then
        audit_check ok "Routage IP actif (machine configuree en routeur pare-feu)" "" ""
    elif [[ "$fwd" == "0" ]]; then
        audit_check ok "Routage IP desactive (machine non routeur)" "" ""
    else
        audit_check ko "Routage IP actif sans role de routeur declare" "" "net.ipv4.ip_forward=0 si cette machine ne route pas." sysctl_fwd
    fi
    rd=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    if [[ "$rd" == "0" ]]; then
        audit_check ok "Redirections ICMP refusees" "" ""
    else
        audit_check ko "Redirections ICMP acceptees" "" "net.ipv4.conf.all.accept_redirects=0 (anti-detournement)." sysctl_redirects
    fi
    if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]]; then
        audit_check ok "SYN cookies actives" "" ""
    else
        audit_check ko "SYN cookies desactives" "" "net.ipv4.tcp_syncookies=1." sysctl_syncookies
    fi

    # 10. Surface d'ecoute
    nb=$(ss -tuln 2>/dev/null | tail -n +2 | wc -l)
    if [[ "${nb:-0}" -le 10 ]]; then
        audit_check ok "Surface d'ecoute reduite ($nb sockets)" "" ""
    else
        audit_check ko "Nombreux services en ecoute ($nb sockets)" "" "Verifiez chaque service (ss -tulnp), desactivez l'inutile (module 8)." privileges
    fi

    # 11. Journalisation
    if systemctl is-active rsyslog >/dev/null 2>&1 || systemctl is-active systemd-journald >/dev/null 2>&1; then
        audit_check ok "Journalisation systeme active" "" ""
    else
        audit_check ko "Journalisation systeme inactive" "" "Activez rsyslog/journald et centralisez (recommandations de journalisation ANSSI)." rsyslog
    fi
    if dpkg -s auditd >/dev/null 2>&1; then
        audit_check ok "auditd present (tracabilite fine)" "" ""
    else
        audit_check ko "auditd absent" "" "apt install auditd : journal d'audit des actions sensibles." auditd
    fi

    local total=$((AUDIT_OK + AUDIT_KO)) pct=0
    (( total > 0 )) && pct=$(( 100 * AUDIT_OK / total ))
    subtitle "Score d'hygiene : $AUDIT_OK/$total controles conformes ($pct %)"
    say "  Resultats conserves pour le rapport (module R)."

    # --- Remediation a la carte : chaque correction est appliquee ou ignoree ---
    if [[ ${#AUDIT_FIXES[@]} -gt 0 ]]; then
        subtitle "Mise en conformite : ${#AUDIT_FIXES[@]} correction(s) proposee(s)"
        say "  Chaque point est propose individuellement (les corrections 'module X'"
        say "  ouvrent le module concerne, les autres appliquent le correctif immediatement)."
        local entry fid flbl
        for entry in "${AUDIT_FIXES[@]}"; do
            fid="${entry%%|*}"; flbl="${entry#*|}"
            if ask_yn "Corriger maintenant : $flbl ?" "${CFG_AUDIT_FIX:-n}"; then
                apply_fix "$fid"
                journal "Audit : correction appliquee ($flbl)"
            else
                info "Ignore : $flbl"
                journal "Audit : correction ignoree ($flbl)"
            fi
        done
        info "Relancez le module 9 pour verifier le nouveau score."
    fi
    mark_done "audit"
    journal "Module 9 : audit d'hygiene realise ($AUDIT_OK/$total conformes, $pct %)"
    pause
}

#===============================================================================
# REGION 12 : MODULE R - RAPPORT HTML
#===============================================================================

html_escape() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

module_report() {
    title "MODULE R : Rapport d'execution"
    local dir="${CFG_REPORT_DIR:-$REPORT_DIR_DEFAULT}"
    local out="$dir/rapport_defense-reseau_$(date '+%Y%m%d_%H%M%S').html"
    if [[ $DRY_RUN -eq 1 ]]; then
        say "${C_CYA}  [SIMULATION]${C_OFF} Generation du rapport HTML dans $dir"
        return 0
    fi
    mkdir -p "$dir"

    {
        cat <<HTML
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport Defense Reseau - $(hostname)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#222;max-width:1000px}
 h1{color:#1a4b8c;border-bottom:3px solid #1a4b8c;padding-bottom:.3em}
 h2{color:#1a4b8c;margin-top:1.6em}
 table{border-collapse:collapse;width:100%;margin:.6em 0}
 th,td{border:1px solid #bbb;padding:.35em .6em;text-align:left;font-size:.92em}
 th{background:#1a4b8c;color:#fff}
 tr:nth-child(even){background:#f4f7fb}
 .ok{color:#1a7a1a;font-weight:bold}.ko{color:#b02020;font-weight:bold}
 .meta{color:#666;font-size:.9em}
</style></head><body>
<h1>Rapport - $SCRIPT_NAME v$SCRIPT_VERSION</h1>
<p class="meta">Machine : <b>$(hostname)</b> &mdash; Genere le $(date '+%d/%m/%Y a %H:%M:%S') &mdash;
Noyau : $(uname -r) &mdash; Distribution : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-inconnue}")</p>
HTML

        echo "<h2>Modules realises</h2><table><tr><th>Module</th><th>Statut</th></tr>"
        local m lbl
        for m in "concepts|1. Concepts et choix des equipements" \
                 "zerotrust|2. Evaluation Zero Trust (NIST SP 800-207)" \
                 "parefeu|3. Pare-feu a zones / DMZ" \
                 "ids|4. IDS / IPS" \
                 "proxy|5. Proxy sortant (Squid)" \
                 "revproxy|6. Reverse proxy" \
                 "bastion|7. Bastion SSH" \
                 "privileges|8. Moindre privilege" \
                 "audit|9. Audit d'hygiene ANSSI"; do
            lbl="${m#*|}"
            if is_done "${m%%|*}"; then
                echo "<tr><td>$lbl</td><td class='ok'>Realise</td></tr>"
            else
                echo "<tr><td>$lbl</td><td>Non realise</td></tr>"
            fi
        done
        echo "</table>"

        if [[ -s "$ZT_TSV" ]]; then
            echo "<h2>Maturite Zero Trust (NIST SP 800-207)</h2><table><tr><th>Principe</th><th>Score</th><th>%</th><th>Niveau</th></tr>"
            while IFS=$'\t' read -r a b c d; do
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                    "$(printf '%s' "$a" | html_escape)" "$b" "$c" "$d"
            done < "$ZT_TSV"
            echo "</table>"
        fi

        if [[ -s "$AUDIT_TSV" ]]; then
            echo "<h2>Audit d'hygiene (referentiels ANSSI)</h2><table><tr><th>Statut</th><th>Controle</th><th>Detail</th><th>Recommandation</th></tr>"
            while IFS=$'\t' read -r st lbl det rec; do
                local cls="ok" txt="Conforme"
                [[ "$st" == "ko" ]] && cls="ko" && txt="A corriger"
                printf '<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                    "$cls" "$txt" \
                    "$(printf '%s' "$lbl" | html_escape)" \
                    "$(printf '%s' "$det" | html_escape)" \
                    "$(printf '%s' "$rec" | html_escape)"
            done < "$AUDIT_TSV"
            echo "</table>"
        fi

        echo "<h2>Journal des etapes</h2><table><tr><th>Horodatage</th><th>Etape</th></tr>"
        while IFS='|' read -r ts msg; do
            printf '<tr><td>%s</td><td>%s</td></tr>\n' "$ts" "$(printf '%s' "$msg" | html_escape)"
        done < "$JOURNAL"
        echo "</table>"

        echo "<h2>Objets crees / fichiers modifies (manifeste)</h2><table><tr><th>Type</th><th>Element</th></tr>"
        while IFS='|' read -r typ path _; do
            printf '<tr><td>%s</td><td>%s</td></tr>\n' "$typ" "$(printf '%s' "$path" | html_escape)"
        done < "$MANIFEST"
        echo "</table>"

        cat <<'HTML'
<h2>Pour aller plus loin</h2>
<ul>
<li>ANSSI - Guide d'hygiene informatique, recommandations reseau, (Open)SSH, TLS, journalisation : cyber.gouv.fr</li>
<li>NIST SP 800-207 Zero Trust Architecture ; CISA Zero Trust Maturity Model</li>
<li>Ce rapport ne contient pas de secret, mais decrit votre defense : diffusion restreinte.</li>
</ul>
</body></html>
HTML
    } > "$out"

    ok "Rapport genere : $out"
    journal "Rapport HTML genere : $out"
    mark_done "rapport"
    pause
}

#===============================================================================
# REGION 13 : MODULE Z - REINITIALISATION 'biere'
#===============================================================================

module_reset() {
    title "MODULE Z : Reinitialisation de ce que le script a cree"
    if [[ $UNATTENDED -eq 1 ]]; then
        err "La reinitialisation est refusee en mode non-interactif."
        return 1
    fi
    if [[ ! -s "$MANIFEST" ]]; then
        info "Manifeste vide : rien a reinitialiser."
        return 0
    fi
    warn "Cette operation restaure les fichiers sauvegardes et supprime UNIQUEMENT"
    warn "les elements traces dans le manifeste ci-dessous :"
    say ""
    sed 's/^/    /' "$MANIFEST"
    say ""
    printf '%s' "${C_BLD}  Pour continuer, tapez exactement le mot '${RESET_KEYWORD}' (sensible a la casse) : ${C_OFF}"
    local word
    read -r word
    if [[ "$word" != "$RESET_KEYWORD" ]]; then
        info "Saisie differente de '$RESET_KEYWORD' : reinitialisation annulee."
        return 0
    fi
    ask_yn "Seconde confirmation : proceder a la restauration/suppression ?" "n" || {
        info "Reinitialisation annulee."
        return 0
    }

    local -a pkgs=() groups=() services=()
    local line typ rest a b
    # Traitement en ordre inverse de creation
    while IFS= read -r line; do
        typ="${line%%|*}"
        rest="${line#*|}"
        a="${rest%%|*}"
        b="${rest#*|}"
        case "$typ" in
            modfile)
                if [[ -n "$b" && -f "$b" ]]; then
                    run_cmd "Restauration de $a" cp -a "$b" "$a"
                else
                    warn "Sauvegarde introuvable pour $a : fichier laisse en l'etat."
                fi
                ;;
            newfile) [[ -e "$a" ]] && run_cmd "Suppression de $a" rm -f "$a" ;;
            dir)     [[ -d "$a" ]] && rmdir "$a" 2>/dev/null && ok "Dossier vide supprime : $a" ;;
            service) services+=("$a") ;;
            pkg)     pkgs+=("$a") ;;
            group)   groups+=("$a") ;;
        esac
    done < <(tac "$MANIFEST")

    local s
    for s in "${services[@]}"; do
        run_cmd "Desactivation du service $s" systemctl disable --now "$s" || true
    done
    if [[ ${#pkgs[@]} -gt 0 ]] && ask_yn "Desinstaller aussi les paquets installes par le script (${pkgs[*]}) ?" "n"; then
        run_cmd "Desinstallation : ${pkgs[*]}" env DEBIAN_FRONTEND=noninteractive apt-get purge -y "${pkgs[@]}"
    fi
    local g
    for g in "${groups[@]}"; do
        if ask_yn "Supprimer le groupe $g ?" "n"; then
            run_cmd "Suppression du groupe $g" groupdel "$g" || true
        fi
    done

    if [[ $DRY_RUN -eq 0 ]]; then
        : > "$MANIFEST"; : > "$DONE_LIST"
    fi
    warn "Pensez a redemarrer les services concernes (ssh, nginx, squid...) et a verifier le pare-feu."
    journal "Reinitialisation '$RESET_KEYWORD' effectuee"
    ok "Reinitialisation terminee. Les journaux et rapports sont conserves."
    pause
}

#===============================================================================
# REGION 14 : MENU PRINCIPAL ET POINT D'ENTREE
#===============================================================================

show_banner() {
    printf '%s\n' "${C_BLD}${C_BLU}"
    cat <<'BANNER'
  =============================================================================
   INIT-DEFENSE-RESEAU - Mise en place interactive de la defense reseau
   Pare-feu/DMZ - IDS/IPS - Proxys - Bastion SSH - Zero Trust - ANSSI
  =============================================================================
BANNER
    printf '%s' "$C_OFF"
    say "  Version $SCRIPT_VERSION - $(date '+%d/%m/%Y %H:%M')  |  Machine : $(hostname)"
    [[ $DRY_RUN -eq 1 ]]    && warn "MODE SIMULATION (--dry-run) : aucune modification ne sera appliquee."
    [[ $UNATTENDED -eq 1 ]] && info "Mode non-interactif : reponses issues de $CONFIG_FILE et des valeurs par defaut."
    [[ $PEDAGO -eq 1 ]]     && info "Mode pedagogique actif (--pedago) : explications detaillees affichees."
}

main_menu() {
    local c
    while true; do
        printf '\n%s\n' "${C_BLD}MENU PRINCIPAL${C_OFF}  ${C_DIM}(defense en profondeur : suivez l'ordre 1 -> 9)${C_OFF}"
        printf '   1) %s Assistant de choix des equipements (architecture)\n' "$(done_mark concepts)"
        printf '   2) %s Zero Trust (NIST SP 800-207) : evaluation + plan d'"'"'action applicable\n' "$(done_mark zerotrust)"
        printf '   3) %s Pare-feu a zones avec DMZ (nftables/iptables + guide OPNsense)\n' "$(done_mark parefeu)"
        printf '   4) %s IDS/IPS (Snort / Suricata) : regles, tuning, threat intel\n' "$(done_mark ids)"
        printf '   5) %s Proxy de filtrage sortant (Squid)\n' "$(done_mark proxy)"
        printf '   6) %s Reverse proxy (Nginx / HAProxy)\n' "$(done_mark revproxy)"
        printf '   7) %s Bastion SSH (durcissement ANSSI, fail2ban)\n' "$(done_mark bastion)"
        printf '   8) %s Moindre privilege (sudo granulaire, umask, services)\n' "$(done_mark privileges)"
        printf '   9) %s Audit d'"'"'hygiene ANSSI + corrections a la carte\n' "$(done_mark audit)"
        printf '   R)        Generer le rapport HTML\n'
        printf '   Z)        Reinitialisation (mot-cle : %s)\n' "$RESET_KEYWORD"
        printf '   Q)        Quitter\n'
        printf '%s' "${C_BLD}  Votre choix : ${C_OFF}"
        read -r c
        case "$c" in
            1) module_concepts ;;
            2) module_zerotrust ;;
            3) module_firewall ;;
            4) module_ids ;;
            5) module_squid ;;
            6) module_revproxy ;;
            7) module_bastion ;;
            8) module_privileges ;;
            9) module_audit ;;
            [rR]) module_report ;;
            [zZ]) module_reset ;;
            [qQ])
                say ""
                if ! is_done "rapport" && ask_yn "Generer le rapport HTML avant de quitter ?" "o"; then
                    module_report
                fi
                say "  Termine. Consultez les journaux et le rapport genere."
                break
                ;;
            *) err "Choix invalide." ;;
        esac
    done
}

unattended_run() {
    local m
    if [[ -z "${CFG_MODULES:-}" ]]; then
        err "Mode --unattended : la variable CFG_MODULES du fichier de configuration est vide."
        err "Exemple : CFG_MODULES=\"parefeu ids proxy bastion audit rapport\""
        exit 1
    fi
    for m in $CFG_MODULES; do
        case "$m" in
            concepts)   module_concepts ;;
            zerotrust)  info "Module zerotrust ignore en mode non-interactif (questionnaire)." ;;
            parefeu)    module_firewall ;;
            ids)        module_ids ;;
            proxy)      module_squid ;;
            revproxy)   module_revproxy ;;
            bastion)    module_bastion ;;
            privileges) module_privileges ;;
            audit)      module_audit ;;
            rapport)    module_report ;;
            *) warn "Module inconnu dans CFG_MODULES : $m" ;;
        esac
    done
}

usage() {
    cat <<USAGE
$SCRIPT_NAME v$SCRIPT_VERSION - defense reseau interactive (Debian/Ubuntu)

Usage : sudo ./Init-DefenseReseau.sh [options]

Options :
  --dry-run, -n          Simulation : montre ce qui serait fait, sans agir
                         (utilisable sans root).
  --unattended           Mode non-interactif (exige --config).
  --config FICHIER       Fichier de configuration (voir config.sample.conf).
  --reset                Lance directement la reinitialisation ('$RESET_KEYWORD').
  --no-color             Desactive les couleurs.
  --pedago               Affiche les explications pedagogiques (methode, schemas,
                         referentiels). Par defaut l'outil est operationnel (sans
                         volet pedagogique).
  --help, -h             Cette aide.

Modules : concepts, zerotrust, pare-feu/DMZ (+guide OPNsense), IDS/IPS
(Snort/Suricata), proxy Squid, reverse proxy (Nginx/HAProxy), bastion SSH
(ANSSI), moindre privilege, audit d'hygiene, rapport HTML, reset '$RESET_KEYWORD'.
USAGE
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run|-n)  DRY_RUN=1 ;;
            --unattended)  UNATTENDED=1 ;;
            --config)      shift; CONFIG_FILE="${1:-}" ;;
            --reset)       DO_RESET=1 ;;
            --no-color)    NO_COLOR=1 ;;
            --pedago)      PEDAGO=1 ;;
            --help|-h)     usage; exit 0 ;;
            *) printf 'Option inconnue : %s\n' "$1" >&2; usage; exit 1 ;;
        esac
        shift
    done

    setup_colors
    require_root
    init_dirs

    if [[ -n "$CONFIG_FILE" ]]; then
        if [[ -f "$CONFIG_FILE" ]]; then
            # shellcheck source=/dev/null
            source "$CONFIG_FILE"
            info "Configuration chargee : $CONFIG_FILE"
        else
            err "Fichier de configuration introuvable : $CONFIG_FILE"
            exit 1
        fi
    fi
    if [[ $UNATTENDED -eq 1 && -z "$CONFIG_FILE" ]]; then
        err "--unattended exige --config FICHIER."
        exit 1
    fi

    journal "Session demarree (v$SCRIPT_VERSION, dry-run=$DRY_RUN, unattended=$UNATTENDED)"
    show_banner
    check_apt || true

    if [[ $DO_RESET -eq 1 ]]; then
        module_reset
        exit 0
    fi
    if [[ $UNATTENDED -eq 1 ]]; then
        unattended_run
        say ""
        ok "Execution non-interactive terminee. Journaux : $LOG_DIR"
        exit 0
    fi
    main_menu
}

main "$@"
                                                                                                     