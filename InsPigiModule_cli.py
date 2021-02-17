import hashlib
import json
import os
# pip install cryptography
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class FileAndHash:
    """
    Classe qui s'occupe de tout se qui est manipulation de données /
    et de cryptographie
    """
    def __init__(self):
        # Initialiser la liste des info
        try:
            with open("data_file.json", "r") as file:
                self.UserName = json.load(file)
        except:
            # si le fichiez ne peut pas etre ouvert, on crer un dico en local 
            self.UserName = {}

    def write_json(self):
        """
        Permet d'ecrire dans le dico
        """
        with open("data_file.json", "w") as write_file:
            json.dump(self.UserName, write_file, indent=4)

    def generateHash(self, pw):
        """
        Genere un hash avec la string( password ) donné

            Parameters:
                pw -> string, qui produira le hash
        """
        salt = os.urandom(32)
        # Creation du salt pour le mdp
        salt2 = os.urandom(32)
        # Creation du salt pour la data
        key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200000)
        # On genere la clé et on return les 3
        return key.hex(), salt.hex(), salt2.hex()

    def goodhash(self, Id, pw):
        """
        Fonction qui verifie si la string( password ) donné est egale a celle stocker
        dans le dico

            Parameters:
                Id -> string, contenu dans le jason qui point un utilisateur,
                permet de retrouver le salt et le mot de passe a comparer
                pw -> string, que l'on va comparer quand elle sera hash
        """
        salt = self.UserName[Id]["SaltPw"]
        salt = bytes.fromhex(salt)
        # On recupere le salt du .json
        new_key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200000)
        new_key = new_key.hex()
        # On encode un nouveau hash avec le soi disant mdp et le salt du .json
        old_key = self.UserName[Id]["hashpw"]
        # On recupere l'ancien hash de l'utilisateur

        if old_key == new_key:# Si les hash sont identique ( meme string de depart)
            self.keyData = self.creatKey(Id, pw) # Creation d'une cle pour les données
            return True
        elif old_key != new_key:# Si les hash ne sont pas identique (pas la meme string de depart)
            return False 

    def creatKey(self, Id, pw):
        """
        Crer une clé pour encoder les données dans le dico

            Parameters:
                Id -> string, contenu dans le jason qui point un utilisateur, permet de retrouver le salt
                pw -> string, qui permet de donner la cle une fois associer au salt

        """
        pw = pw.encode() # on encode en byte
        salt = self.UserName[Id]["SaltData"] # on trouve le salt
        salt = bytes.fromhex(salt) 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        ) # creation de la key 
        key = base64.urlsafe_b64encode(kdf.derive(pw))  # Can only use kdf once
        return key 

    def Encrypting(self, message):
        """
        Fonction qui encrypte a l'aide de la clé stocker dans self.keyData

            Parameters: 
                message -> string, a encrypter 
        """
        message = message.encode()
        f = Fernet(self.keyData)
        encrypted = f.encrypt(
            message
        )  # Encrypt the bytes. The returning object is of type bytes
        return encrypted

    def Decrypting(self, data):
        """
        Fonction qui decrypt a l'aide de la clé stocker dans self.keyData

            Parameters:
                message -> string, a decrypt 
        """
        data = bytes.fromhex(data)
        f = Fernet(self.keyData)
        decrypted = f.decrypt(
            data
        )  # Decrypt the bytes. The returning object is of type bytes
        return decrypted


class Compte(FileAndHash):
    """
    Classe qui s'occupe de tout se qui est manipulaation du compte
    """
    def __init__(self):
        # initalisation
        super().__init__()
        # initialise la classe parent 
        self.connected = False
        self.user_connect = None
        # Personne n'est connecter

    def connection(self, Id, pw):
        """
        Fonction qui permet a l'utilisateur de se connecter

        Id -> string, qui permet de chercher l'utilisateur dans le dico

        pw -> string, qui est sensé etre le mdp de l'user, verification par le hash
        """
        if self.connected == False:
            if Id in self.UserName:  # Si le compte existe
                goodpw = self.goodhash(Id, pw) # boolean , True si c le bon mdp False autrement
                if goodpw == True:
                    self.connected = True # un utilisateur est connecter 
                    self.user_connect = Id # specification de l'utilisateur 
                    return "Login success"
                elif goodpw == False: 
                    return "Login Failed, Your Username and/or Password do not match"
            else:
                return "Login Failed, Your username does not exist"
        else:
            return "Sorry, you are already login"

    def deconnection(self):
        """ 
        Fonction qui deconnecte l'user
        """
        if self.connected == True:
            self.connected = False
            return "Deconnection success"
        else:
            return "You are already deconneted "

    def suppr(self):
        """
        Fonction pour supprimer le compte d'un utilisateur 
        """
        if self.connected == True:
            print(
                "Cette action est irreversible\nVoulez vous vraiment supprimer le compte {}".format(
                    self.user_connect
                )
            )
            answer = input((str("""\t1- Yes \n\t2- No \t\n\ninput : """)))
            if answer != "1": # si il se resigne
                return "Compte non supprimer"
            print("\nVeuillez rentre votre mot de passe pour continuer")
            pw = str(input("\t: "))  # rentrer le mdp pr etre sur de son choix
            goodpw = self.goodhash(self.user_connect, pw) # boolean , True si c le bon mdp False autrement
            if goodpw == True:
                del self.UserName[self.user_connect]  # supprimer la cle du dico
                self.write_json() # ecrit dans le fichiez
                self.deconnection() # se deco
                return "Delete success"
            elif goodpw == False:
                return "Delete Failed, Your Username and/or Password do not match"
        else:
            return "Sorry, you have to be connected to do this action"

    def inscription(self, Id, pw):
        """
        Fonction qui permet de s'inscrire

            Parameters:
            Id -> string, Nom d'utilisateur
            pw -> string, Mot de passe 
        """

        if self.connected == False:
            if Id in self.UserName: # si il existe deja 
                return "Username already takeout"
            hashpw, saltpw, saltData = self.generateHash(pw) # renvois les hashs et les salts associer au compte

            self.UserName[Id] = {
                "User": Id,
                "hashpw": hashpw,
                "SaltPw": saltpw,
                "SaltData": saltData,
                "Data": None,
            } # Ajout dans le dico
            self.write_json() # On ecrit le nouveau dico 
            return "Incription succes"
        else:
            return "You have to be conneted to perform this"

    def return_etat_connection(self):
        """
        Renvois l'etat de connection
        """
        return self.connected

    def return_connected_user(self):
        """
        Renvois l'utilisateur connecter
        """
        return self.user_connect

    def writeData(self, data):
        """
        Ecrire dans la data

        Parameters:
            data -> string, que on veut ecrire 
        """ 
        data = self.Encrypting(data) # On crypt l'input de l'utilisateur 
        Id = self.return_connected_user() # on recuper l'utilisateur connecter
        self.UserName[Id]["Data"] = data # on recrit par dessu les données de l'utlisateur 
        self.write_json() # on ecrit le nouveau dico 

    def readData(self, Id):
        """
        lire dans la data
            Parameters:
                Id -> string, nom de l'utilisateur 
        """ 
        data = self.UserName[Id]["Data"] # On recupere la data de l'utilisateur Id 
        data = self.Decrypting(data)  # on la decrypte avec la clé de l'utilisateur 
        return data


# Todo :
# rendre sa plus lisible
# Modifier les nom de variable
# Gui
# modifier les classes
# dictionnaire en data
# ajouter les commentaires 

if __name__ == "__main__":

    def logo():
        os.system("cls")

        logo = """
      ___              ____   _         _  __  __             _         _       
     |_ _| _ __   ___ |  _ \ (_)  __ _ (_)|  \/  |  ___    __| | _   _ | |  ___ 
      | | | '_ \ / __|| |_) || | / _` || || |\/| | / _ \  / _` || | | || | / _ \\
      | | | | | |\__ \|  __/ | || (_| || || |  | || (_) || (_| || |_| || ||  __/
     |___||_| |_||___/|_|    |_| \__, ||_||_|  |_| \___/  \__,_| \__,_||_| \___|
                                 |___/                                                                       
            """
        print(logo)

    def ask_id_pw():
        Id = input("\nVeuillez entrer votre nom d'utilisateur : ")
        Pw = input("Veuillez entrer votre mot de passe      : ")
        print("")
        return str(Id).strip(), str(Pw).strip()

    # Font Name: Univers
    # Font Name: Stop

    logo()
    DataBase = Compte()
    etat = DataBase.return_etat_connection()
    AccesData = False
    requete = "Try Again"

    boucle = True
    while boucle:
        if AccesData == False:
            if etat == False:
                inp = input(
                    str(
                        "\n Que voulez vous faire ? \n\t 1- Vous inscrire \n\t 2- Vous connecter \n\n input : "
                    )
                )
                if inp == "1":
                    Id, Pw = ask_id_pw()
                    requete = DataBase.inscription(str(Id), str(Pw))
                elif inp == "2":
                    Id, Pw = ask_id_pw()
                    requete = DataBase.connection(str(Id), str(Pw))
                else:
                    requete = "Try Again"
            elif etat == True:
                print(
                    "\n Connecter en tant que : "
                    + DataBase.return_connected_user()
                    + "\n"
                )
                inp = input(
                    str(
                        " Que voulez vous faire ?\n\t1- Supprimer votre compte\n\t2- Vous decconecter\n\t3- Manipuler votre Data\n\n input : "
                    )
                )
                if inp == "1":
                    requete = DataBase.suppr()
                elif inp == "2":
                    logo()
                    requete = DataBase.deconnection()
                elif inp == "3":
                    requete = "successful data access"
                    AccesData = True
                else:
                    requete = "Try Again"

            etat = DataBase.return_etat_connection()
            logo()
            print("====> " + requete + " <====")
        elif AccesData == True:
            inp = input(
                "\n Que voulez vous faire ?\n\t1- Lire vos données\n\t2- Ecrire dans vos données\n\t3- Revenir en arriere \n\n input : "
            )
            if inp == "1":
                try:
                    data = DataBase.readData(DataBase.return_connected_user())
                    data = data.decode("utf-8")
                except:
                    data = "None"
                data = str(data)
                logo()
                print("====> " + "Data read with sucess" + " <====\n")
                print("Données du compte de " + DataBase.return_connected_user())
                print(" : " + data)
            if inp == "2":
                try:
                    data = DataBase.readData(DataBase.return_connected_user())
                    data = data.decode("utf-8")
                except:
                    data = "None"
                data = str(data)
                logo()
                print("====> " + "Data read with sucess" + " <====\n")
                print("Données du compte de " + DataBase.return_connected_user())
                print(" : " + data)
                inp2 = input("\nQue voulez vous ecrire ? \ninput : ")
                print(DataBase.writeData(inp2))
                logo()
                print("====> " + "Data write with sucess" + " <====")
            elif inp == "3":
                logo()
                AccesData = False
