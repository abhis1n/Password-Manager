import json
import string
import os
import random

from Crypto.Cipher import AES
from halo import Halo
from termcolor import colored

from modules.exceptions import *


class DataManip:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": [
            "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]}
        self.checkmark_ = "\u2713"
        self.x_mark_ = "\u2717"
        self.specialChar_ = "!@#$%^&*()-_"

    def savePassword(self, filename, data, nonce, website):
        spinner = Halo(text=colored("Saving", "green"),
                       spinner=self.dots_, color="green")
        spinner.start()
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as jsondata:
                    jfile = json.load(jsondata)
                jfile[website]["nonce"] = nonce
                jfile[website]["password"] = data
                with open(filename, 'w') as jsondata:
                    json.dump(jfile, jsondata, sort_keys=True, indent=4)
            except KeyError:
                with open(filename, 'r') as jsondata:
                    jfile = json.load(jsondata)
                jfile[website] = {}
                jfile[website]["nonce"] = nonce
                jfile[website]["password"] = data
                with open(filename, 'w') as jsondata:
                    json.dump(jfile, jsondata, sort_keys=True, indent=4)
        else:
            jfile = {website: {}}
            jfile[website]["nonce"] = nonce
            jfile[website]["password"] = data
            with open(filename, 'w') as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)
        spinner.stop()
        print(
            colored(f"{self.checkmark_} Saved successfully. Thank you!", "green"))

    def encrypt_data(self, filename, data, master_pass, website):

        concatenated_master = master_pass + "="*16

        key = concatenated_master[:16].encode("utf-8")

        cipher = AES.new(key, AES.MODE_EAX)

        nonce = cipher.nonce.hex()

        data_to_encrypt = data.encode("utf-8")

        encrypted_data = cipher.encrypt(data_to_encrypt).hex()

        self.savePassword(filename, encrypted_data, nonce, website)

    def decrypt_data(self, master_pass, website, filename):
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as jdata:
                    jfile = json.load(jdata)
                nonce = bytes.fromhex(jfile[website]["nonce"])
                password = bytes.fromhex(jfile[website]["password"])
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

        formatted_master_pass = master_pass + "="*16
        master_pass_encoded = formatted_master_pass[:16].encode("utf-8")
        cipher = AES.new(master_pass_encoded, AES.MODE_EAX, nonce=nonce)
        plaintext_password = cipher.decrypt(password).decode("utf-8")

        return plaintext_password

    def generate_password(self):
        password = []
        length = input("Enter Length for Password (At least 8): ")

        if length.lower().strip() == "exit":
            raise UserExits
        elif length.strip() == "":
            raise EmptyField
        elif int(length) < 8:
            raise PasswordNotLongEnough
        else:

            spinner = Halo(text=colored("Generating Password",
                           "green"), spinner=self.dots_, color="green")
            spinner.start()
            for i in range(0, int(length)):

                password.append(random.choice(random.choice(
                    [string.ascii_lowercase, string.ascii_uppercase, string.digits, self.specialChar_])))

            finalPass = "".join(password)
            spinner.stop()

            return finalPass

    def list_passwords(self, filename):
        if os.path.isfile(filename):
            with open(filename, 'r') as jsondata:
                pass_list = json.load(jsondata)

            passwords_lst = ""
            for i in pass_list:
                passwords_lst += "--{}\n".format(i)

            if passwords_lst == "":
                raise PasswordFileIsEmpty
            else:
                return passwords_lst
        else:
            raise PasswordFileDoesNotExist

    def delete_password(self, filename, website):
        if os.path.isfile(filename):
            with open(filename, 'r') as jdata:
                jfile = json.load(jdata)

            try:
                jfile.pop(website)
                with open("db/passwords.json", 'w') as jdata:
                    json.dump(jfile, jdata, sort_keys=True, indent=4)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist
