import nmap  # Importation du module nmap pour l'analyse réseau
import requests  # Importation du module requests pour les requêtes HTTP
from itertools import product  # Importation du module itertools pour les combinaisons de produit cartésien

# Fonction pour analyser un réseau
def analyser_reseau(reseau):
    nm = nmap.PortScanner()  # Création d'un scanner nmap
    nm.scan(hosts=reseau, arguments='-sV')  # Scanner le réseau spécifié pour les services ouverts
    for hote in nm.all_hosts():  # Boucle sur tous les hôtes découverts
        print(f'Hôte: {hote} ({nm[hote].hostname()})')  # Afficher l'hôte et son nom
        print(f'État: {nm[hote].state()}')  # Afficher l'état de l'hôte (up/down)
        for proto in nm[hote].all_protocols():  # Boucle sur tous les protocoles détectés
            print(f'Protocole: {proto}')  # Afficher le protocole (tcp/udp)
            ports = nm[hote][proto].keys()  # Obtenir les ports pour ce protocole
            for port in ports:  # Boucle sur tous les ports détectés
                print(f'Port: {port}\tÉtat: {nm[hote][proto][port]["state"]}\tService: {nm[hote][proto][port]["name"]}')  # Afficher le port, son état et le service associé
    return nm  # Retourner l'objet scanner

# Fonction pour tester les vulnérabilités sur une URL
def tester_vulnerabilites_url(url):
    urls_test = [f'{url}/admin', f'{url}/login', f'{url}/test', f'{url}/phpinfo.php']  # Liste des chemins URL à tester
    for url_test in urls_test:  # Boucle sur chaque URL de test
        try:
            reponse = requests.get(url_test)  # Faire une requête GET à l'URL de test
            if reponse.status_code == 200:  # Si le statut HTTP est 200 (OK)
                print(f'Vulnérabilité potentielle trouvée à {url_test}')  # Signaler une vulnérabilité potentielle
            else:
                print(f'{url_test} a retourné {reponse.status_code}')  # Afficher le statut HTTP retourné
        except requests.RequestException as e:  # En cas d'exception lors de la requête
            print(f'Erreur d\'accès à {url_test}: {e}')  # Afficher l'erreur

# Fonction pour tester l'intrusion par force brute
def tester_intrusion(url, utilisateurs, mots_de_passe):
    for utilisateur, mot_de_passe in product(utilisateurs, mots_de_passe):  # Boucle sur toutes les combinaisons de noms d'utilisateur et mots de passe
        try:
            reponse = requests.post(url, data={'username': utilisateur, 'password': mot_de_passe})  # Faire une requête POST avec les données de connexion
            if reponse.status_code == 200 and "Login failed" not in reponse.text:  # Si le statut HTTP est 200 et que le texte de réponse ne contient pas "Login failed"
                print(f'Intrusion réussie avec {utilisateur}:{mot_de_passe}')  # Signaler une intrusion réussie
                return  # Arrêter le test après une réussite
        except requests.RequestException as e:  # En cas d'exception lors de la requête
            print(f'Erreur de connexion à {url}: {e}')  # Afficher l'erreur
    print('Intrusion échouée avec toutes les combinaisons testées.')  # Signaler l'échec de toutes les tentatives d'intrusion

# Point d'entrée principal du script
if __name__ == '__main__':
    print("Analyseur de Vulnérabilités Réseau et Testeur d'Applications Web")  # Afficher le titre du script
    reseau_cible = input("Entrez le réseau cible (ex. : 192.168.1.0/24) : ")  # Demander à l'utilisateur d'entrer le réseau cible
    url_cible = input("Entrez l'URL cible (ex. : http://exemple.com) : ")  # Demander à l'utilisateur d'entrer l'URL cible
    url_login = input("Entrez l'URL de connexion (ex. : http://exemple.com/login) : ")  # Demander à l'utilisateur d'entrer l'URL de connexion

    print("\nAnalyse du réseau en cours...")  # Afficher un message indiquant le début de l'analyse réseau
    analyser_reseau(reseau_cible)  # Appeler la fonction d'analyse réseau

    print("\nTest des URL pour les vulnérabilités en cours...")  # Afficher un message indiquant le début du test des vulnérabilités URL
    tester_vulnerabilites_url(url_cible)  # Appeler la fonction de test des vulnérabilités URL

    # Utilisateurs et mots de passe de test
    utilisateurs = ['admin', 'user', 'test']  # Liste des noms d'utilisateur de test
    mots_de_passe = ['password', '123456', 'admin']  # Liste des mots de passe de test

    print("\nTest d'intrusion par force brute en cours...")  # Afficher un message indiquant le début du test d'intrusion par force brute
    tester_intrusion(url_login, utilisateurs, mots_de_passe)  # Appeler la fonction de test d'intrusion

