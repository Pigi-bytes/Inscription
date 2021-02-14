import base64
import hashlib
import json
import os
import tkinter.font as tkFont
from tkinter import *
from tkinter.messagebox import askyesno

# pip install cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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

        Id -> string, contenu dans le jason qui point un utilisateur,
              permet de retrouver le salt
        
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
        
        message -> string, a decrypt 
        """
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

            Parameters:
                Id -> string, qui permet de chercher l utilisateur dans le dico
                pw -> string, qui est sensé etre le mdp de l user, verification par le hash
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
                return "Login Failed, Your Username and/or Password do not match"
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
            del self.UserName[self.user_connect]  # supprimer la cle du dico
            self.write_json() # ecrit dans le fichiez
            return "Delete success"
        else:
            return "Sorry, you have to be connected to do this action"

    def inscription(self, Id, pw):
        """
        Fonction qui permet de s'inscrire

            Parameters:

                Id -> string, Nom d utilisateur
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
            return "You dosen't have to be connected to perform this"

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
        data = data.decode("utf-8") # on la converti
        Id = self.return_connected_user() # on recuper l'utilisateur connecter
        self.UserName[Id]["Data"] = data # on recrit par dessu les données de l'utlisateur 
        self.write_json() # on ecrit le nouveau dico 

    def readData(self):
        """
        lire dans la data
        """ 
        data = self.UserName[self.user_connect]["Data"] # On recupere la data de l'utilisateur Id 
        if data == None:
            return "Empty"
        data = data.encode()  # On la converti 
        data = self.Decrypting(data)  # on la decrypte avec la clé de l'utilisateur 
        return data


class Application(Compte):
    """
    Une classe pour gerer la Gui de l'application
    """
    def __init__(self,fenetre):
        super().__init__()
        self.fen = fenetre

        self.fen.title("InsPigiModule")
        # pathfile = os.path.dirname(os.path.abspath(__file__))
        # self.fen.iconphoto(True, PhotoImage(file=pathfile + '\icone.png'))
        # self.fen.geometry("450x400")
        self.policeMenu = ('Helvetic', 10)
        self.initUx()

    def initUx(self):
        self.Frame_First_Panel = Frame(self.fen, bd="0.5")
        self.Frame_First_Panel.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Frame qui permet de centrer les 3 autres dans la fenetre 

        WelcomeBackFrame = Frame(self.Frame_First_Panel,)
        WelcomeBackFrame.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Frame qui permet d'afficher le texte Welcome Back

        InscriptionFrame = Frame(self.Frame_First_Panel,)
        InscriptionFrame.grid(column=0, row=2, padx=5, pady=10, sticky=N)
        # Frame qui permet de gerer les deux inscription

        Frame_Box = Frame(self.Frame_First_Panel, bd="2",  bg="#000000")
        Frame_Box.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # Frame qui sert de boite pour les modules de connections

        Frame_Box_2 = Frame(Frame_Box,)
        Frame_Box_2.grid(column=0, row=1, padx=0, pady=0, sticky=N)
        # Permet de separer la box bleu en deux

        Frame_Box_Pw = Frame(Frame_Box_2, )
        Frame_Box_Pw.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Frame avec les inputs dedans

        self.LabelAbove = Label(WelcomeBackFrame, text="Welcome Back :", font = self.policeMenu)
        self.LabelAbove.grid(column=0, row=0, padx=5, pady=5, sticky=S)
        # Texte Welcome back
        
        self.Button_In = Button(Frame_Box_2, text="Sign In",font = self.policeMenu, command=self.connectionGui)
        self.Button_In.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # Button pour se connecter 

        self.LabelInfoConnection = Label(Frame_Box_2, text= "", fg="#F00000")
        self.LabelInfoConnection.grid(column=0, row=2, padx=5, pady=5, sticky=N)
        self.LabelInfoConnection.configure(font=("Helvetic", 10, "italic"))


        self.LabelSign = Label( InscriptionFrame, text="Don't have an account ?", font = self.policeMenu,)
        self.LabelSign.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # text for Don't have an account ?

        self.Button_Sign = Button(InscriptionFrame, text="Sign Up", font = self.policeMenu, command=self.SignUPaccountPannel)
        self.Button_Sign.grid(column=1, row=0, padx=5, pady=10)
        # Button pour se connecter 

        self.EntryId = Entry(Frame_Box_Pw, width=25, fg='Grey', font = self.policeMenu,)
        EntryIdText = 'Username :'
        self.EntryId.insert(0,EntryIdText)
        
        self.EntryId.bind("<FocusIn>", lambda args: self.focus_in_entry_box(self.EntryId))
        self.EntryId.bind("<FocusOut>", lambda args: self.focus_out_entry_box(self.EntryId, EntryIdText))

        self.EntryId.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Input du UserName

        self.EntryPw = Entry(Frame_Box_Pw, width=25, fg='Grey', font = self.policeMenu,)
        EntryPwText = 'Password :'
        self.EntryPw.insert(0,EntryPwText)

        self.EntryPw.bind("<FocusIn>", lambda args: self.focus_in_entry_box(self.EntryPw))
        self.EntryPw.bind("<FocusOut>", lambda args: self.focus_out_entry_box(self.EntryPw, EntryPwText))

        self.EntryPw.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # Input du Password

        self.SignINaccountPannel()

    def SignINaccountPannel(self):
        """
        Fonction qui permet de basculer l'affiche principal en SignIn
        """
        self.LabelAbove.config(text="Welcome Back :")
        self.Button_In.config(text="Connection",command = self.connectionGui)
        self.LabelSign.config(text="Don't have an account ?")
        self.Button_Sign.config(text="Sign Up", command=self.SignUPaccountPannel)
        self.LabelInfoConnection.configure(text=" ")

    def SignUPaccountPannel(self):
        """
        Fonction qui permet de basculer l'affiche principal en SignUp
        """
        self.LabelAbove.config(text="Create a new account :")
        self.Button_In.config(text="Create a new account", command = self.inscriptionGui)
        self.LabelSign.config(text="Already have a account ?")
        self.Button_Sign.config(text="Sign In", command=self.SignINaccountPannel)
        self.LabelInfoConnection.configure(text=" ")

    def focus_out_entry_box(self, widget, widget_text):
        """
        Fonction pour afficher du texte dans les entry non utiliser
        """
        if widget['fg'] == 'Black' and len(widget.get()) == 0:
            widget.delete(0, END)
            widget['fg'] = 'Grey'
            widget.insert(0, widget_text)

    def focus_in_entry_box(self, widget):
        """
        Fonction pour afficher du texte dans les entry non utiliser 2
        """
        if widget['fg'] == 'Grey':
            widget['fg'] = 'Black'
            widget.delete(0, END)

    def GetValidEntry(self, widget):
        """
        Fonction qui permet de savoir si on a un message d'erreur ou si on peut rentrer
        """
        if widget['fg'] == 'Grey' or widget.get() == "":
            self.LabelInfoConnection.configure(text="All entry must be completed")
            return False
        else:
            return widget.get()
            
    def connectionGui(self):
        """
        Fonction qui permet de se connecter a l'aide de la gui
        """
        Id = self.GetValidEntry(self.EntryId)
        Pw =  self.GetValidEntry(self.EntryPw)
        if Id and Pw != False:
            etat = super().connection(Id, Pw)
            if etat == "Login success":
                print("Connecter")
                self.connectedUx()
            else:
                self.LabelInfoConnection.configure(text=etat)

    def inscriptionGui(self):
        """
        Fonction qui permet de s'inscrire a l'aide de la gui 
        """
        Id = self.GetValidEntry(self.EntryId)
        Pw =  self.GetValidEntry(self.EntryPw)
        if Id and Pw != False:
            etat = super().inscription(Id, Pw)
            if etat == "Incription succes":
                print("Inscrit")
                super().connection(Id, Pw)
                self.connectedUx()
            else:
                self.LabelInfoConnection.configure(text=etat)

    def connectedUx(self):
        """
        Fonction qui permet d'afficher la fenetre quand on est connecter
        """

        self.Frame_First_Panel.grid_forget() # on enleve le panel de connection 

        self.FrameConnected = Frame(self.fen, bd="1") # Creation d'un nouveau panel
        self.FrameConnected.grid(column=0, row=0, padx=5, pady=10, sticky=N) # on l'affiche

        texteDeBase = super().readData()
        self.text_widget = Text(self.FrameConnected, wrap='word', exportselection=0, font=self.policeMenu, height = 10, width = 50)  # Widget de text
        self.text_widget.insert("1.0", texteDeBase)
        self.text_widget.grid(column=0, row=0, padx=5, pady=10, sticky=NSEW) 

        ButtonSave = Button(self.FrameConnected, text='Save', command=self.SaveCommand)
        ButtonSave.grid(column=0, row=1, padx=5, pady=10, sticky=N)

        self.FrameSetting = Frame(self.FrameConnected, bd="1")
        self.FrameSetting.grid(column=1, row=0, padx=5, pady=10, sticky=NSEW)
        self.setting = False

        CompteTexte = super().return_connected_user()
        Texte = "Setting of {} account".format(CompteTexte)
        
        ButtonCompte = Button(self.FrameSetting, text=Texte, font=self.policeMenu, command = self.clickSetting)
        ButtonCompte.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        
    def SaveCommand(self):
        """
        Fonction qui permet de sauvegarder le texte 
        """
        Data = self.text_widget.get("1.0", END)
        super().writeData(Data)

    def clickSetting(self):
        """
        Fonction qui permet d'afficher les options quand on clique sur le profil
        """
        if self.setting == False:
            # Si rien n'est afficher afficher
            self.setting = True

            self.ButtonDeco = Button(self.FrameSetting, text="Disconnection", font=self.policeMenu, command = self.DeconnectionGui)
            self.ButtonDeco.grid(column=0, row=1, padx=5, pady=2, sticky=N)

            self.ButtonSuppr = Button(self.FrameSetting, text="Supprimer votre compte", font=self.policeMenu, command = self.SupprGui)
            self.ButtonSuppr.grid(column=0, row=2, padx=5, pady=2, sticky=N)

        elif self.setting == True:
            #sinon enlever 
            self.setting = False
            self.ButtonDeco.grid_forget()
            self.ButtonSuppr.grid_forget()

    def DeconnectionGui(self):
        """
        Fonction pour se deconnecter a l'aide de la gui
        """

        self.FrameConnected.grid_forget()
        super().deconnection()
        self.initUx()

    def SupprGui(self):
        """
        Fonction pour supprimer son compte GUI
        """
        answer = askyesno(title='Delete account', message='Are you sure that you want to delete your account')
        if answer == True:
            super().suppr()
            self.DeconnectionGui()
        

if __name__ == "__main__":
    # Creation d'une fenetre 
    root = Tk()
    Application(root)
    root.mainloop()
