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
    Class that takes care of all data manipulation / and cryptography
    """
    def __init__(self):
        # Initialize the dico
        try:
            with open("data_file.json", "r") as file:
                self.dico_data = json.load(file)
                # we open the file and put it in a dictionary
        except:
           # if the file cannot be opened, we create a dico locally
            self.dico_data = {}

    def write_json(self):
        """
        Function that allows you to write in the dictionary
        """
        with open("data_file.json", "w") as write_file:
            json.dump(self.dico_data, write_file, indent=4)
            # we open the file and write "self.dico_data" in the dictionary

    def generate_hash(self, key):
        """
        Generate a hash with the character string enter
        return the hash, the salt that was used and a second salt for later, 
        in hexadecimal form.

            Parameters
                key -> string, Character chain that will produce the hash
        """
        salt = os.urandom(32)
        # Creation of the salt for the password 
        # use of urandom for random encryption
        salt2 = os.urandom(32)
        # Creation of the salt for the data
        # use of urandom for random encryption

        hash1 = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, 200000)
        # We generate the hash with the hashlib function, 
        # iteration of the sha256 200,000 times with the salt  
        return hash1.hex(), salt.hex(), salt2.hex()

    def good_hash(self, Id, pw):
        """
        Function that checks if the given string is equal to the stored one
        in dictionary,
        returns true if the two hashes are the same, else, it False

            Parameters
                Id -> string, that indicates where the user is stored in the .json
                pw -> string, that we will compare with the one 
                      stored in the dictionary
        """
        salt = self.dico_data[Id]["SaltPw"]
        salt = bytes.fromhex(salt)
        # we get the salt from the .json
        new_key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 200000)
        new_key = new_key.hex()
        # We encode a new hash with the so-called password and the salt of the .json
        old_key = self.dico_data[Id]["hashpw"]
        # We retrieve the hash stored with the user

        if old_key == new_key:
            # If the two hashes are identical
            # then the password is equal to the character string
            self.keyData = self.creat_key(Id, pw) 
            # We create a key to be able to encode the data associated with the account
            return True
        elif old_key != new_key:
            # If the hashes are not identical
            # We know that the character string is not the same as the password
            return False 

    def creat_key(self, Id, pw):
        """
        Creation of a key to save the data in the dictionary, return the key

            Parameters: 
                Id -> string, that indicates where the user is stored in the .json
                pw -> string,string, character chain that will produce the hash

        """
        pw = pw.encode()
        # We encode in utf-8
        salt = self.dico_data[Id]["SaltData"] 
        salt = bytes.fromhex(salt) 
        # we get the salt from the .json
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()) 
            # Creation of the encryption key for the data
            # 200_000 iteration of the sha256
        key = base64.urlsafe_b64encode(kdf.derive(pw)) 
        # We encode the key with the kdf and base64 method
        return key 

    def encryptions(self, message):
        """
        Function that encrypts the message string using the key stored in the dico

            Parameters:
                message -> string, data to encrypt
        """
        message = message.encode() 
        # We encode the string in utf-8
        f = Fernet(self.keyData)
        encrypted = f.encrypt(message)  
        # Encrypt the bytes
        return encrypted.hex()
        # we return the Hexadecimal version of the byte encrypt

    def decryption(self, data):
        """
        Function that decrypts the message string using the key stored in the dico
            Parameters:
                message -> string, data to decrypt
        """
        data = bytes.fromhex(data) 
        # We convert the Hexadecimal to Bytes
        f = Fernet(self.keyData)
        decrypted = f.decrypt(data) 
        # we Decrypt the bytes
        return decrypted 
        # we return the decryptions of the byte, a string

    def flush_key_data(self):
        """
        function taht reset key for crypting/decrpting the data
        """
        self.keyData = None 
        

class Compte(FileAndHash):
    """
    class that takes care of all that is account manipulation
    """
    def __init__(self):
        # initialization
        super().__init__()
        # initializes the parent class
        self.connected = False
        self.user_connect = None

    def connection(self, Id, pw):
        """
        Function that allows the user to connect to his account

            Parameters:
                Id -> string, User Name that indicates where the user is stored in the .json
                pw -> string, User Password, used to connect to the account
        """
        if self.connected == False:
            # if no one is connected
            if Id in self.dico_data: 
                # If id is in the dictionary 
                # so that the user already has an account
                goodpw = self.good_hash(Id, pw) 
                # We see if the password is the same as the one associated with the account
                if goodpw == True:
                    # if they are the same
                    self.connected = True 
                    # We indicate that a user is connected
                    self.user_connect = Id 
                    # we say who is connecting
                    return "Login success"
                elif goodpw == False: 
                    # If the two password aren't the same
                    return "Login Failed, Your Username and/or Password do not match"
            else:
                # if the account dosen't existe 
                return "Login Failed, Your Username and/or Password do not match"
        else:
            # if someone is already connected
            return "Sorry, you are already login"

    def deconnection(self):
        """ 
        Function that allows the user to be disconnected from his account
        """
        if self.connected == True:
            # if someone is connected
            self.flush_key_data()
            self.connected = False
            self.user_connect = None
            # We say no one is connected
            return "Deconnection success"
        else:
            # if no one is connected
            return "You are already deconneted "

    def delete_account(self):
        """
        function that allows you to delete your account
        """
        if self.connected == True:
            # if someone is connected
            del self.dico_data[self.user_connect]  
            # we remove it from the dictionary
            self.write_json() 
            # we write the changes in the dictionary
            return "Delete success"
        else:
            # if no one is connected
            return "Sorry, you have to be connected to do this action"

    def inscription(self, Id, pw):
        """
        Function that allows you to register

            Parameters:
                Id -> string, The account username
                pw -> string, User password
        """
        if self.connected == False:
            # if no one is connected
            if Id in self.dico_data: 
                # if the username is already in the dictionnary 
                return "Username already takeout"
            hash_pw, salt_pw, salt_data = self.generate_hash(pw) 
            # we hash the password to store it so that it cannot be read in the JSON
            # we we also recover the salt and the salt associated with the key for encrypting the data 
            self.dico_data[Id] = {
                "User": Id,
                "hashpw": hash_pw,
                "SaltPw": salt_pw,
                "SaltData": salt_data,
                "Data": None,
            } # we write this on the dico
            self.write_json() # On ecrit le nouveau dico 
            return "Incription succes"
        else:
            # if someone is connected we can't do this 
            return "You dosen't have to be connected to perform this"

    def return_etat_connection(self):
        """
        We return the connection status
        """
        return self.connected

    def return_connected_user(self):
        """
        Renvois l'utilisateur connecter
        """
        return self.user_connect

    def write_data(self, data):
        """
        function to  write the data in the dictionary

            Parameters:
                data -> string, information we write to the file
        """ 
        data = self.encryptions(data) 
        # we encrypt the information
        Id = self.return_connected_user() 
        #we look which user to connect
        self.dico_data[Id]["Data"] = data 
        # we replace user data with new ones
        self.write_json() 
        # we update the dictionary

    def read_data(self):
        """
        function to read the data of the user, return a string 
        """ 
        data = self.dico_data[self.user_connect]["Data"] 
        # we retrieve the data associated with the user connected 
        if data == None:
            # if there is no data
            return "Empty"
        data = self.decryption(data)  
        # we decrypt the data
        return data


class Application(Compte):
    """
    a class to manage the graphical interface
    """
    def __init__(self,fenetre):
        super().__init__()
        self.fen = fenetre
        # the main app 

        self.fen.title("InsPigiModule")
        # pathfile = os.path.dirname(os.path.abspath(__file__))
        # self.fen.iconphoto(True, PhotoImage(file=pathfile + '\icone.png'))
        # self.fen.geometry("450x400")
        self.policeMenu = ('Helvetic', 10)
        # we indicate the police
        self.init_ux_first_panel()
        self.sign_in_panel()

    def init_ux_first_panel(self):
        """
        Class which allows to display the frames of the first window
        """
        self.frame_first_panel = Frame(self.fen, bd="0.5")
        self.frame_first_panel.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Main frame, allowing to center the others

        label_up = Frame(self.frame_first_panel,)
        label_up.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Frame that contains the text above

        inscriptions_frame = Frame(self.frame_first_panel,)
        inscriptions_frame.grid(column=0, row=2, padx=5, pady=10, sticky=N)
        # Frame which contains the button to switch to the other menu

        frame_box_connections = Frame(self.frame_first_panel, bd="2",  bg="#000000")
        frame_box_connections.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # Frame used to center the connection module

        frame_box_connections2 = Frame(frame_box_connections,)
        frame_box_connections2.grid(column=0, row=1, padx=0, pady=0, sticky=N)
        # Frame which allows to separate the frame in two

        frame_input = Frame(frame_box_connections2, )
        frame_input.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # Frame with the inputs inside

        self.label_above = Label(label_up, text=" ", font = self.policeMenu)
        self.label_above.grid(column=0, row=0, padx=5, pady=5, sticky=S)
        # Text displayed above the window

        self.button_connection_panel = Button(frame_box_connections2, text=" ",font = self.policeMenu, command=self.connection_gui)
        self.button_connection_panel.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # Button pour se connecter 

        self.label_error = Label(frame_box_connections2, text= " ", fg="#F00000")
        self.label_error.grid(column=0, row=2, padx=5, pady=5, sticky=N)
        self.label_error.configure(font=("Helvetic", 10, "italic"))
        # text to display errors

        self.label_below = Label( inscriptions_frame, text=" ", font = self.policeMenu,)
        self.label_below.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # text for the label below 

        self.boutton_milieu = Button(inscriptions_frame, text=" ", font = self.policeMenu, command=self.sign_up_panel)
        self.boutton_milieu.grid(column=1, row=0, padx=5, pady=10)
        # Button pour se connecter 

        self.EntryId = Entry(frame_input, width=25, fg='Grey', font = self.policeMenu,)
        EntryIdText = 'Username :'
        self.EntryId.insert(0,EntryIdText)
        self.EntryId.bind("<FocusIn>", lambda args: self.focus_in_entry_box(self.EntryId))
        self.EntryId.bind("<FocusOut>", lambda args: self.focus_out_entry_box(self.EntryId, EntryIdText))
        self.EntryId.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # inputs for username

        self.EntryPw = Entry(frame_input, width=25, fg='Grey', font = self.policeMenu,)
        EntryPwText = 'Password :'
        self.EntryPw.insert(0,EntryPwText)
        self.EntryPw.bind("<FocusIn>", lambda args: self.focus_in_entry_box(self.EntryPw))
        self.EntryPw.bind("<FocusOut>", lambda args: self.focus_out_entry_box(self.EntryPw, EntryPwText))
        self.EntryPw.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # inputs for the password

    def sign_in_panel(self):
        """
        Function that allows to switch the main display to connect
        """
        self.label_above.config(text="Welcome Back :")
        self.button_connection_panel.config(text="Connection",command = self.connection_gui)
        self.label_below.config(text="Don't have an account ?")
        self.boutton_milieu.config(text="Sign Up", command=self.sign_up_panel)
        self.label_error.configure(text=" ")
        # we configure the new texts and buttons

    def sign_up_panel(self):
        """
        Function that allows to switch the main display to register
        """
        self.label_above.config(text="Create a new account :")
        self.button_connection_panel.config(text="Create a new account", command = self.inscription_gui)
        self.label_below.config(text="Already have a account ?")
        self.boutton_milieu.config(text="Sign In", command=self.sign_in_panel)
        self.label_error.configure(text=" ")
         # we configure the new texts and buttons

    def focus_out_entry_box(self, widget, widget_text):
        """
        functions to display text in the entry if no text is entered
        """
        if widget['fg'] == 'Black' and len(widget.get()) == 0:
            # if the color of the entered text is black, and there is nothing written in it
            widget.delete(0, END)
            # we delete to be sure
            widget['fg'] = 'Grey'
            # we change the color to be grey
            widget.insert(0, widget_text)
            # we insert the text 

    def focus_in_entry_box(self, widget):
        """
        Function to delete the text displayed when nothing is entered
        """
        if widget['fg'] == 'Grey':
            # if the color is grey
            widget['fg'] = 'Black'
            # we change the color to black
            widget.delete(0, END)
            # we delete all 

    def get_valid_entry(self, widget):
        """
        function to check if the information entered in the fields is correct
        """
        if widget['fg'] == 'Grey' or widget.get() == "":
            # if the color of the widget is grey , or if the lenght of the input is 0 
            self.label_error.configure(text="All entry must be completed")
            # We show that on the labelerror 
            return False
        else:
            # if the entry is corect
            return widget.get() 
            
    def connection_gui(self):
        """
        Function that allows you to connect from the graphical interface
        call when you click on the button
        """
        Id = self.get_valid_entry(self.EntryId)
        # we get the username
        Pw =  self.get_valid_entry(self.EntryPw)
        # we get the password
        if Id and Pw != False:
            # if the two inpus are not wrong
            etat = super().connection(Id, Pw)
            # we get what the connection returns
            if etat == "Login success":
                # if it good
                self.connected_ux()
            else:
                # if it not login success
                self.label_error.configure(text=etat)
                # we affich the error on the label for that

    def inscription_gui(self):
        """
        Function that allows you to register from the graphical interface
        call when you click on the button
        """
        Id = self.get_valid_entry(self.EntryId)
        # we get the username
        Pw =  self.get_valid_entry(self.EntryPw)
        # we get the password
        if Id and Pw != False:
            # if the two inpus are not wrong
            etat = super().inscription(Id, Pw)
            # we get what the connection returns
            if etat == "Incription succes":
                # if it good
                super().connection(Id, Pw)
                self.connected_ux()
            else:
                # if it not login success
                self.label_error.configure(text=etat)
                # we affich the error on the label for that

    def connected_ux(self):
        """
        Function to display the window when a user is logged in
        """
        self.frame_first_panel.grid_forget() 
        # we remove the previous panel

        self.frame_connected = Frame(self.fen, bd="1")
        self.frame_connected.grid(column=0, row=0, padx=5, pady=10, sticky=N) 
        # we create a new panel for the window

        texteDeBase = super().read_data()
        # The data of the account
        self.text_widget = Text(self.frame_connected, wrap='word', exportselection=0, font=self.policeMenu, height = 10, width = 50)  # Widget de text
        self.text_widget.insert("1.0", texteDeBase)
        self.text_widget.grid(column=0, row=0, padx=5, pady=10, sticky=NSEW) 
        # Create where the text is written

        button_save = Button(self.frame_connected, text='Save', command=self.save_command)
        button_save.grid(column=0, row=1, padx=5, pady=10, sticky=N)
        # button to save the written text

        self.frame_setting = Frame(self.frame_connected, bd="1")
        self.frame_setting.grid(column=1, row=0, padx=5, pady=10, sticky=NSEW)
        self.setting = False
        # frame to show the setting od the account

        CompteTexte = super().return_connected_user()
        Texte = "Setting of {} account".format(CompteTexte)
        # retrieve user login

        button_account = Button(self.frame_setting, text=Texte, font=self.policeMenu, command = self.click_setting)
        button_account.grid(column=0, row=0, padx=5, pady=10, sticky=N)
        # button display with username on top
        
    def save_command(self):
        """
        function which allows to save the text in the widget into the account
        """
        Data = self.text_widget.get("1.0", END)
        super().write_data(Data)

    def click_setting(self):
        """
        function to display the button by clicking on the settings
        """
        if self.setting == False:
            # if nothing is displayed
            self.setting = True
            # we say that something is to display
            self.button_logout = Button(self.frame_setting, text="Disconnection", font=self.policeMenu, command = self.decconection_gui)
            self.button_logout.grid(column=0, row=1, padx=5, pady=2, sticky=N)
            # button to log out

            self.boutton_delete = Button(self.frame_setting, text="Supprimer votre compte", font=self.policeMenu, command = self.delete_gui)
            self.boutton_delete.grid(column=0, row=2, padx=5, pady=2, sticky=N)
            # button to delete your account

        elif self.setting == True:
            # if something is displayed
            self.setting = False
            self.button_logout.grid_forget()
            self.boutton_delete.grid_forget()
            # we delete it

    def decconection_gui(self):
        """
        function to disconnect from the graphical interface
        """
        self.frame_connected.grid_forget()
        # we delete the frame 
        super().deconnection()
        # we disconnect
        self.init_ux_first_panel()

    def delete_gui(self):
        """
        Function to delete your account
        """
        answer = askyesno(title='Delete account', message='Are you sure that you want to delete your account')
        if answer == True:
            # if the user want realy to delete is account
            super().delete_account()
            # we delete it 
            self.decconection_gui()
        

if __name__ == "__main__":
    root = Tk()
    Application(root)
    root.mainloop()
