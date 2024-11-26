import sys
import getpass
import pyperclip

from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import *

from Crypto.Cipher import AES

import numpy as np

from PIL import Image

nonce = ""
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

        if choice == "6":
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
                                f"{self.obj_.x_mark_} Some error. {self.obj_.x_mark_}",
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

        elif choice == "4":

            try:
                self.stegno_password()
                return self.begin()
            except UserExits:
                raise UserExits

        elif choice == "5":
            try:
                self.stegno_password_decrypt()
                return self.begin()
            except UserExits:
                raise UserExits

    def menu_prompt(self):

        print(colored("\n\t*Enter 'exit' at any point to exit.*\n", "magenta"))
        print(colored("1) Add/Update a password", "blue"))
        print(colored("2) Look up a stored password", "blue"))
        print(colored("3) Delete a password", "blue"))
        print(colored("4) Save password into image", "blue"))
        print(colored("5) Decrypt password from image", "blue"))
        print(colored("6) Exit program", "blue"))

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

    def stegno_password(self):
        global nonce
        ip = input("Enter password: ")

        concatenated_master = self.masterPass + "="*16

        key = concatenated_master[:16].encode("utf-8")

        cipher = AES.new(key, AES.MODE_EAX)

        nonce = cipher.nonce

        data_to_encrypt = ip.encode("utf-8")

        encrypted_data = cipher.encrypt(data_to_encrypt).hex()

        print(encrypted_data)

        # save into image
        # get binary
        ascii_values = np.array([ord(char) for char in encrypted_data], dtype=int)

        binary_array = np.zeros((len(ascii_values), 8), dtype=int)

        for i, ascii_value in enumerate(ascii_values):
            for bit_position in range(8):
                binary_array[i, bit_position] = (ascii_value >> (7 - bit_position)) & 1

        # get Image
        # Scale binary values (0 or 1) to grayscale (0 or 255)
        grayscale_array = binary_array * 255
        output_file="binary_image.png"

        # Create an image from the array
        image = Image.fromarray(grayscale_array.astype('uint8'), mode='L')  # 'L' mode for grayscale

        # Save the image to a file
        image.save(output_file)
        print(f"Image saved as {output_file}")

        # print(binary_array)
        # print(binary_array2)
        # working, tested

        self.begin()

    def stegno_password_decrypt(self):
        global nonce
        concatenated_master = self.masterPass + "="*16

        key = concatenated_master[:16].encode("utf-8")

        # check image read
        # Open the image
        output_file="binary_image.png"
        image = Image.open(output_file).convert('L')  # 'L' mode for grayscale

        # Convert the image to a numpy array
        grayscale_array = np.array(image)

        # Threshold the grayscale values to binary (0 or 1)
        binary_array2 = (grayscale_array // 255)
        # decrypt
        # Convert each row of the 2D binary array into an 8-bit binary string
        binary_strings = [''.join(str(bit) for bit in row) for row in binary_array2]

        # Convert the binary strings into their corresponding characters
        characters = [chr(int(binary_string, 2)) for binary_string in binary_strings]

        # Join the characters into a single string
        result_string = ''.join(characters)

        # check decryption
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt(bytes.fromhex(result_string)).decode("utf-8")
        print("Decrypted data:", decrypted_data)

        self.begin()