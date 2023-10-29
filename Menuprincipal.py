import hashlib
import rsa
import bcrypt
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_sha256(word):
    hashed_word = hashlib.sha256(word.encode()).hexdigest()
    print(f"Le mot haché par sha256 est : {hashed_word}")

def hash_with_salt(word):
    salt = bcrypt.gensalt()
    hashed_word = bcrypt.hashpw(word.encode(), salt)
    print(f"Le mot haché avec salt est : {hashed_word}")

def dictionary_attack(hashed_password):
    with open('dictionary.txt', 'r') as file:
        for word in file.readlines():
            word = word.strip()
            hashed_word = hash_password(word)
            if hashed_word == hashed_password:
                return word
        return None
       
def generate_key_pairs():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key)
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key)
    print("Key pairs generated and saved in private_key.pem and public_key.pem.")

def encrypt_message(message):
    with open("public_key.pem", "rb") as public_file:
        public_key = RSA.import_key(public_file.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    with open("private_key.pem", "rb") as private_file:
        private_key = RSA.import_key(private_file.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

def sign_message(message):
    with open("private_key.pem", "rb") as private_key_file:
        private_key_data = private_key_file.read()
        private_key = RSA.import_key(private_key_data)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(message, signature):
    with open("public_key.pem", "rb") as public_key_file:
        public_key_data = public_key_file.read()
        public_key = RSA.import_key(public_key_data)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("La signature est valide.")
    except (ValueError, TypeError):
        print("Signature invalide.")


def generate_self_signed_certificate():
    with open("private_key.pem", "rb") as private_file:
        private_key = RSA.import_key(private_file.read())
    
    certificate = {
        "public_key": private_key.publickey().export_key().decode(),
        "signature": None
    }
    h = hashlib.sha256(certificate["public_key"].encode()).digest()
    certificate["signature"] = private_key.sign(h, '')
    with open("certificate.pem", "wb") as cert_file:
        cert_file.write(certificate["public_key"].encode())
        cert_file.write(b'\n')
        cert_file.write(base64.b64encode(certificate["signature"]))
    print("Self-signed certificate generated and saved in certificate.pem.")       

def encrypt_with_certificate(message):
    with open("certificate.pem", "rb") as cert_file:
        public_key = RSA.import_key(cert_file.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message    


def Menu():
    while True:
     print("Menu Principal:")
     print("A- Donnez un mot à hacher")
     print("    a- Hacher le mot par sha256")
     print("    b- Hacher le mot en générant un salt (bcrypt)")
     print("    c- Attaquer par dictionnaire le mot inséré")
     print("    d- Revenir au menu principal")
     print("B- Chiffrement (RSA)")
     print("    a- Générer les paires de clés dans un fichier")
     print("    b- Chiffrer un message de votre choix par RSA")
     print("    c- Déchiffrer le message (b)")
     print("    d- Signer un message de votre choix par RSA")
     print("    e- Vérifier la signature du message (d)")
     print("    f- Revenir au menu principal")
     print("C- Certificat (RSA)")
     print("    a- Générer les paires de clés dans un fichier")
     print("    b- Générer un certificat autosigné par RSA")
     print("    c- Chiffrer un message de votre choix par ce certificat")
     print("    d- Revenir au menu principal")
     choix = input("Choisissez une option : ")
     if choix.upper() == "A":
        mot = input("Entrez le mot à hacher : ")
        choix_a = input("Choisissez une option (a, b, c, d) : ")
        if choix_a.lower() == "a":
            hash_sha256(mot)
        elif choix_a.lower() == "b":
            hash_with_salt(mot)
        elif choix_a.lower() == "c":
            hashpass = hash_password(mot)
            word = dictionary_attack(hashpass)
            if word is not None:
                print(f"Le mot trouvé est : {word}")
            else:
                    print("Mot non trouvé")
        elif choix_a.lower() == "d":
            continue

     elif choix.upper() == "B":
        choix_b = input("Choisissez une option (a, b, c, d, e, f) : ")

        if choix_b.lower() == "a":
            generate_key_pairs()
        elif choix_b.lower() == "b":
            messageb = input("Entrez le message à chiffrer : ")
            encrypted_message = encrypt_message(messageb, )
            print(f"Le message chiffré est : {encrypted_message}")
        elif choix_b.lower() == "c":
            res =decrypt_message(encrypted_message)
            print(f"Le message déchiffré est : {res}")
        elif choix_b.lower() == "d":
            messaged = input("Entrez le message à signer : ")
            signatured = sign_message(messaged)
            print(f"La signature du message est : {signatured}")
        elif choix_b.lower() == "e":
            verify_signature(messaged, signatured)
        elif choix_b.lower() == "f":
            continue

     elif choix.upper() == "C":
        choix_c = input("Choisissez une option (a, b, c, d) : ")

        if choix_c.lower() == "a":
            generate_key_pairs()
        elif choix_c.lower() == "b":
            generate_self_signed_certificate()
            
        elif choix_c.lower() == "c":
            messagesing = input("donner message : ")
            signemessage =encrypt_with_certificate(messagesing)
            print(f"Le message chiffre avec certificate RSA   est : {signemessage}")
        elif choix_c.lower() == "d":
            continue
     else:
        print("Option invalide. Veuillez réessayer.")

Menu()