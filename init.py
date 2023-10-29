import colorama
import art
import cowsay
print(art.text2art("welcom TN"))
print(colorama.Fore.BLUE)
cowsay.cow("app chiffrement and Certificat RSA")

def menup():
    print("1: Enregistre vous")
    print("2: Login")
    print("3: Quiter app")
while True:
    menup()
    choix=input("tapper votre choix : ")
    match choix:
        case '1':
         import enregistrement
         import Authentification
         enregistrement.Enregistrer_client()
        case '2':
         import Authentification
         Authentification.login()
        case '3':
          exit()
        case default:
          print("choix invalide. Veuiller sélectionner un option valide ")
          
    