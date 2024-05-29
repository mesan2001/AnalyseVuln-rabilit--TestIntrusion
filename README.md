# Analyse de Vulnérabilité et Test d'Intrusion

## Description
Ce projet propose un script simple pour l'analyse de vulnérabilité réseau et les tests d'intrusion de
base pour les applications web. Il utilise `nmap` pour l'analyse de réseau et `requests` pour tester 
les vulnérabilités des applications web et effectuer des tests d'intrusion par force brute.

## Fonctionnalités
- Analyse un réseau pour détecter les ports ouverts et les services.
- Teste des URL communes pour des vulnérabilités potentielles.
- Effectue des tests d'intrusion par force brute sur une page de connexion.

## Prérequis
- Python 3.x
- nmap (à installer via le gestionnaire de paquets de votre système)
- python-nmap
- requests

## Installation
1. Installez `nmap` en utilisant le gestionnaire de paquets de votre système :
    ```bash
    sudo apt-get install nmap  # pour Ubuntu/Debian
    ```
2. Clonez le dépôt :
    ```bash
    git clone https://github.com/votreutilisateur/analyse-vulnerabilite-teste-intrusion.git
    cd analyse-vulnerabilite-teste-intrusion
    ```
3. Installez les dépendances Python :
    ```bash
    pip install -r requirements.txt #contient les dépendances
    ```

## Utilisation
Exécutez le script et suivez les instructions pour entrer le réseau cible et les URL :
```bash
python analyse_vulnerabilite_teste_intrusion.py
