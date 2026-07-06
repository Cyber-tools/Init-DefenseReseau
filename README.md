# Init-DefenseReseau

Pendant **Linux** d'`Init-WindowsServer.ps1` : script Bash **interactif** de mise en
place de la défense réseau d'un environnement Debian/Ubuntu, construit sur le même
modèle (menus, mode simulation, mode non-interactif par fichier de configuration,
journalisation, manifeste des objets créés, rapport final, réinitialisation « biere »),
avec un volet **pédagogique** avant chaque action.

## Objectifs couverts

| # | Module | Objectif |
|---|---|---|
| 1 | Concepts | Connaître les moyens de défense, savoir **choisir les équipements** (panorama + assistant de choix), défense en profondeur, référentiels ANSSI |
| 2 | Zero Trust | Maîtriser le modèle **NIST SP 800-207** : les 7 principes, évaluation de maturité interactive (14 questions), puis **plan d'action opérationnel applicable** : inventaire local généré, mises à jour automatiques, journalisation d'audit, lancement direct des modules 3/4/7 — chaque action au choix |
| 3 | Pare-feu | Configurer **nftables ou iptables** : politique par défaut DROP, zones **WAN/LAN/DMZ**, NAT, publication de services en DMZ, anti-verrouillage (rollback 60 s) + **guide OPNsense** généré |
| 4 | IDS/IPS | Déployer **Snort** (apprentissage) ou **Suricata** (production) : écriture de règles locales commentées, **tuning** (threshold/suppress), **threat intel** (ET Open via suricata-update), passage IPS optionnel |
| 5 | Proxy | **Squid** en filtrage sortant : ACL, liste noire de domaines, `deny all` final, journalisation |
| 6 | Reverse proxy | **Nginx ou HAProxy** : terminaison TLS, en-têtes de sécurité (HSTS, X-Frame-Options...), contrôle de santé des backends |
| 7 | Bastion SSH | Durcissement sshd selon le guide **ANSSI (Open)SSH** : clés uniquement, `AllowGroups`, algorithmes récents, bannière légale, **fail2ban**, guide ProxyJump généré |
| 8 | Moindre privilège | Audit sudoers, délégation sudo **granulaire** (validée par `visudo -cf`), umask 027, pwquality, désactivation des services inutiles |
| 9 | Audit | Vérifications inspirées du Guide d'hygiène informatique de l'ANSSI avec score, puis **corrections à la carte** : chaque point non conforme est proposé individuellement (appliquer ou ignorer) — MAJ, sysctl persistés, permissions, verrouillage de comptes, rsyslog/auditd/fail2ban... |
| R | Rapport | Rapport **HTML** : modules réalisés, scores Zero Trust et audit, journal horodaté, manifeste |
| Z | Reset | Réinitialisation protégée par la saisie exacte du mot **`biere`** : restaure les fichiers sauvegardés, supprime uniquement ce qui a été créé et tracé |

## Prérequis

- Debian 11/12 ou Ubuntu 22.04/24.04 (paquets installés via `apt`)
- Bash, exécution en **root** (`sudo`) — sauf en simulation
- Accès Internet uniquement pour l'installation des paquets et les règles ET Open

## Utilisation

```bash
chmod +x Init-DefenseReseau.sh

# Interactif (recommandé : suivre l'ordre 1 -> 9)
sudo ./Init-DefenseReseau.sh

# Simulation : montre ce qui serait fait, sans rien modifier (root non requis)
./Init-DefenseReseau.sh --dry-run

# Non-interactif, piloté par un fichier de configuration
sudo ./Init-DefenseReseau.sh --unattended --config config.sample.conf

# Réinitialisation de ce que le script a créé (mot-clé 'biere')
sudo ./Init-DefenseReseau.sh --reset
```

## Garde-fous intégrés

- **Chaque action est un choix** : le script *applique réellement* les mesures
  (paquets, fichiers de configuration, services, règles), mais toujours après
  une question o/n — vous mettez en place ou vous ignorez, action par action.
- **Pare-feu** : après application des règles, confirmation demandée sous
  **60 secondes**, sinon l'ancien jeu de règles est **restauré automatiquement**
  (anti-verrouillage). Le port SSH est demandé explicitement.
- **Bastion SSH** : l'authentification par mot de passe n'est désactivée **que si
  une clé publique est déjà installée** ; la configuration est validée par
  `sshd -t` avant redémarrage (sinon le fichier de durcissement est retiré).
- **sudoers** : tout fichier de délégation est validé par `visudo -cf` avant
  installation.
- **IDS/IPS** : démarrage systématique en mode détection (IDS) ; le mode IPS
  (nfqueue, trafic en coupure) est optionnel et accompagné d'avertissements.
- **Idempotence** : chaque fichier modifié est sauvegardé horodaté dans
  `/var/lib/init-defense-reseau/sauvegardes/`, chaque objet créé est tracé dans
  le manifeste ; le script est relançable sans doublon.

## État, journaux et rapport

| Emplacement | Contenu |
|---|---|
| `/var/lib/init-defense-reseau/` | manifeste, journal des étapes, modules terminés |
| `/var/lib/init-defense-reseau/sauvegardes/` | copies horodatées des fichiers modifiés |
| `/var/lib/init-defense-reseau/logs/` | journal détaillé de chaque session |
| `/root/Rapports-DefenseReseau/` | rapport HTML, guide OPNsense, guide bastion |

## Réinitialisation « biere »

Comme pour `Init-WindowsServer.ps1` : le script trace **chaque élément qu'il crée**
(fichiers, sauvegardes, paquets, groupes, services). La remise à zéro exige la saisie
**exacte** du mot `biere`, affiche le récapitulatif, demande une seconde confirmation,
restaure les fichiers sauvegardés et ne supprime **que** les éléments tracés. La
désinstallation des paquets et la suppression des groupes exigent des confirmations
séparées. Refusée en mode `--unattended`.

## Avertissements

> ⚠️ Outil conçu pour des **labs, maquettes et petits environnements**, dans une
> démarche d'apprentissage. Testez en maquette avant toute production : un pare-feu
> en politique DROP, un sshd durci ou un proxy obligatoire peuvent couper des usages
> existants. Les certificats générés (reverse proxy) sont **auto-signés** : en
> production, utilisez une PKI ou Let's Encrypt.

## Références

- ANSSI — Guide d'hygiène informatique (42 mesures) ; Recommandations relatives à
  l'interconnexion d'un SI à Internet ; Recommandations pour la définition d'une
  politique de filtrage réseau d'un pare-feu ; Recommandations pour un usage
  sécurisé d'(Open)SSH ; Recommandations de sécurité relatives à TLS ;
  Recommandations pour la journalisation — [cyber.gouv.fr](https://cyber.gouv.fr)
- NIST **SP 800-207** — Zero Trust Architecture ; CISA — Zero Trust Maturity Model
- Emerging Threats Open (threat intelligence gratuite pour Suricata/Snort)

## Licence

[MIT](LICENSE) — et si ce script vous a sauvé la vie... *payez une bière à
Quentin et Max à l'occasion !* 🍺
