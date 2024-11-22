import sys
import getpass
import pyperclip

from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import *


class Manager:
    def __init__(
        self, obj: DataManip, filename: str, master_file: str, master_pass: str
    ):
        self.obj_ = obj
        self.filename_ = filename
        self.master_file_ = master_file
        self.masterPass = master_pass

    def begin(self):
        try:

            choice = self.menu_prompt()
        except UserExits:
            raise UserExits

        if choice == "4":
            raise UserExits

        if choice == "1":

            try:
                self.update_db()
                return self.begin()
            except UserExits:
                raise UserExits

        elif choice == "2":

            try:
                string = self.load_password()
                website = string.split(":")[0]
                password = string.split(":")[1]
                print(colored(f"Password for {website}: {password}", "yellow"))

                copy_to_clipboard = input(
                    "Copy password to clipboard? (Y/N): ").strip()
                if copy_to_clipboard == "exit":
                    raise UserExits
                elif copy_to_clipboard == "y":
                    try:
                        pyperclip.copy(password)
                        print(
                            colored(
                                f"{self.obj_.checkmark_} Password copied to clipboard",
                                "green",
                            )
                        )
                    except pyperclip.PyperclipException:
                        print(
                            colored(
                                f"{self.obj_.x_mark_} If you see this message on Linux use `sudo apt-get install xsel` for copying to work. {self.obj_.x_mark_}",
                                "red",
                            )
                        )
                else:
                    pass

                return self.begin()
            except UserExits:
                raise UserExits
            except PasswordFileDoesNotExist:
                print(
                    colored(
                        f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.begin()

        elif choice == "3":

            try:
                return self.delete_password()
            except UserExits:
                raise UserExits

        elif choice == "5":

            try:
                self.delete_db(self.masterPass)
            except MasterPasswordIncorrect:
                print(
                    colored(
                        f"{self.obj_.x_mark_} Master password is incorrect {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.delete_db(self.masterPass)
            except UserExits:
                raise UserExits

        elif choice == "6":

            try:
                self.delete_all_data(self.masterPass)
            except MasterPasswordIncorrect:
                print(
                    colored(
                        f"{self.obj_.x_mark_} Master password is incorrect {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.delete_all_data(self.masterPass)
            except UserExits:
                raise UserExits

    def menu_prompt(self):

        print(colored("\n\t*Enter 'exit' at any point to exit.*\n", "magenta"))
        print(colored("1) Add/Update a password", "blue"))
        print(colored("2) Look up a stored password", "blue"))
        print(colored("3) Delete a password", "blue"))
        print(colored("4) Exit program", "blue"))

        choice = input("Enter a choice: ")

        if choice == "":
            return self.menu_prompt()
        elif choice == "exit":
            raise UserExits
        else:
            return choice.strip()

    def __return_generated_password(self, website):
        try:
            generated_pass = self.obj_.generate_password()
            print(colored(generated_pass, "yellow"))

            loop = input("Generate a new password? (Y/N): ")
            if loop.lower().strip() == "exit":
                raise UserExits
            elif (loop.lower().strip() == "y") or (loop.strip() == ""):
                return self.__return_generated_password(website)
            elif loop.lower().strip() == "n":
                return generated_pass
        except (PasswordNotLongEnough, EmptyField):
            print(colored("Password length invalid.", "red"))
            return self.__return_generated_password(website)
        except UserExits:
            print(colored("Exiting...", "red"))
            sys.exit()

    def update_db(self):
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            pass
        except PasswordFileDoesNotExist:
            print(colored(f"--There are no passwords stored.--", "yellow"))

        website = input(
            "Enter the website for which you want to store a password (ex. google.com): "
        )
        if website.lower() == "":

            self.update_db()
        elif website.lower().strip() == "exit":
            raise UserExits
        else:
            gen_question = input(
                "Do you want to generate a password for {} ? (Y/N): ".format(
                    website)
            )
            if gen_question.strip() == "":

                self.update_db()
            elif gen_question.lower().strip() == "exit":
                raise UserExits
            elif gen_question.lower().strip() == "n":
                password = input("Enter a password for {}: ".format(website))
                if password.lower().strip() == "exit":
                    raise UserExits
                else:
                    self.obj_.encrypt_data(
                        self.filename_, password, self.masterPass, website
                    )

            elif gen_question.lower().strip() == "y":
                password = self.__return_generated_password(website)
                self.obj_.encrypt_data(
                    "db/passwords.json", password, self.masterPass, website
                )

    def load_password(self):
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()
        website = input(
            "Enter website for the password you want to retrieve: ")

        if website.lower().strip() == "exit":
            raise UserExits
        elif website.strip() == "":
            return self.load_password()
        else:
            try:
                plaintext = self.obj_.decrypt_data(
                    self.masterPass, website, self.filename_
                )
            except PasswordNotFound:
                print(
                    colored(
                        f"{self.obj_.x_mark_} Password for {website} not found {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.load_password()
            except PasswordFileDoesNotExist:
                print(
                    colored(
                        f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.begin()

            final_str = f"{website}:{plaintext}"

            return final_str

    def list_passwords(self):
        print(colored("Current Passwords Stored:", "yellow"))
        spinner = Halo(
            text=colored("Loading Passwords", "yellow"),
            color="yellow",
            spinner=self.obj_.dots_,
        )

        try:
            lst_of_passwords = self.obj_.list_passwords(self.filename_)
            spinner.stop()
            print(colored(lst_of_passwords, "yellow"))
        except PasswordFileIsEmpty:
            lst_of_passwords = "--There are no passwords stored.--"
            spinner.stop()
            print(colored(lst_of_passwords, "yellow"))
            raise PasswordFileIsEmpty
        except PasswordFileDoesNotExist:
            raise PasswordFileDoesNotExist

    def delete_password(self):
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()

        website = input(
            "What website do you want to delete? (ex. google.com): "
        ).strip()

        if website == "exit":
            raise UserExits
        elif website == "":
            return self.delete_password()
        else:
            try:
                self.obj_.delete_password(self.filename_, website)
                print(
                    colored(
                        f"{self.obj_.checkmark_} Data for {website} deleted successfully.",
                        "green",
                    )
                )
                return self.begin()
            except PasswordNotFound:
                print(
                    colored(
                        f"{self.obj_.x_mark_} {website} not in DB {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.delete_password()
            except PasswordFileDoesNotExist:
                print(
                    colored(
                        f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}",
                        "red",
                    )
                )
                return self.begin()
