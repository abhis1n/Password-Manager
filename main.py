import os
import json
import sys
import getpass

from os.path import isfile
from hashlib import sha256
from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import UserExits, PasswordFileDoesNotExist
from modules.menu import Manager


def exitProgram():
    print(colored("Exiting...", "red"))
    sys.exit()


def start(obj: DataManip):
    if os.path.isfile("db/masterpassword.json"):
        with open("db/masterpassword.json", 'r') as jsondata:
            jfile = json.load(jsondata)

        storedMasterPass = jfile["Master"]
        masterPass = getpass.getpass("Enter Your Master Password: ")

        spinner = Halo(text=colored("Unlocking", "green"),
                       color="green", spinner=obj.dots_)
        if sha256(masterPass.encode("utf-8")).hexdigest() == storedMasterPass:
            print(
                colored(f"{obj.checkmark_} Thank you! Choose an option below:", "green"))

            menu = Manager(obj, "db/passwords.json",
                           "db/masterpassword.json", masterPass)

            try:
                menu.begin()
            except UserExits:
                exitProgram()
            except PasswordFileDoesNotExist:
                print(colored(
                    f"{obj.x_mark_} DB not found. Try adding a password {obj.x_mark_}", "red"))
        else:
            print(
                colored(f"{obj.x_mark_} Master password is incorrect {obj.x_mark_}", "red"))
            return start(obj)

    else:
        try:
            os.mkdir("db/")
        except FileExistsError:
            pass

        print(colored("To start, we'll have you create a master password. Be careful not to lose it as it is unrecoverable.", "green"))
        masterPass = getpass.getpass(
            "Create a master password for the program: ")
        secondInput = getpass.getpass("Verify your master pasword: ")

        if masterPass == secondInput:
            spinner = Halo(text=colored("initializing base...",
                           "green"), color="green", spinner=obj.dots_)
            hashMasterPass = sha256(masterPass.encode("utf-8")).hexdigest()
            jfile = {"Master": {}}
            jfile["Master"] = hashMasterPass
            with open("db/masterpassword.json", 'w') as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)
            spinner.stop()
            print(colored(
                f"{obj.checkmark_} Thank you! Restart the program and enter your master password to begin.", "green"))
        else:
            print(colored(
                f"{obj.x_mark_} Passwords do not match. Please try again {obj.x_mark_}", "red"))
            return start(obj)


if __name__ == "__main__":
    obj = DataManip()
    start(obj)
