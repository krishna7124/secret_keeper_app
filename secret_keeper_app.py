import os
import bcrypt
from cryptography.fernet import Fernet
import getpass

def check_duplicate_username(username):
    # Check if the given username already exists in the users.txt file
    with open("data/users.txt", "r") as user_file:
        lines = user_file.readlines()
        existing_usernames = [line.split(",")[0].lower() for line in lines]
    return username.lower() in existing_usernames

def initialize_project():
    # Create necessary directories and files if they don't exist
    if not os.path.exists("data"):
        os.makedirs("data")
        with open("data/users.txt", "w") as user_file:
            pass
        with open("data/deleted_users.txt", "w") as deleted_users_file:
            pass

def hash_password(password, salt):
    # Hash the password using bcrypt
    password_bytes = password.encode('utf-8')
    salt_bytes = salt if isinstance(salt, bytes) else salt.encode('utf-8')
    return bcrypt.hashpw(password_bytes, salt_bytes)

def save_user_to_file(username, salt, password_hash, first_name, last_name, age, email):
    # Save user data to the users.txt file
    with open("data/users.txt", "a") as user_file:
        user_file.write(f"{username},{salt},{password_hash},{first_name},{last_name},{age},{email}\n")

def save_deleted_user(username, salt, password_hash, first_name, last_name, age, email):
    with open("data/deleted_users.txt", "a") as deleted_users_file:
        deleted_users_file.write(f"{username},{salt},{password_hash},{first_name},{last_name},{age},{email}\n")

def encrypt_secret(secret):
    # Encrypt the secret using Fernet symmetric encryption
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_secret = cipher_suite.encrypt(secret.encode('utf-8'))
    print("\n🔒 Secret encrypted successfully!")
    return key, encrypted_secret

def decrypt_secret(key, encrypted_secret):
     # Decrypt the secret using Fernet symmetric decryption
    cipher_suite = Fernet(key)
    decrypted_secret = cipher_suite.decrypt(encrypted_secret)
    return decrypted_secret.decode('utf-8')

def add_secret_to_file(username, key, encrypted_secret):
     # Add encrypted secret to the user's secrets file
    with open(f"data/{username}_secrets.txt", "a") as secrets_file:
        secrets_file.write(f"{key.decode('utf-8')},{encrypted_secret.decode('utf-8')}\n")

def get_user_secrets(username):
    # Retrieve and decrypt user's secrets from the secrets file
    secrets_list = []
    secrets_file_path = f"data/{username}_secrets.txt"
    if os.path.exists(secrets_file_path):
        with open(secrets_file_path, "r") as secrets_file:
            lines = secrets_file.readlines()
            for line in lines:
                key, encrypted_secret = line.strip().split(",")
                decrypted_secret = decrypt_secret(key.encode('utf-8'), encrypted_secret.encode('utf-8'))
                secrets_list.append(decrypted_secret)
    return secrets_list

def delete_secret_from_file(username, secret):
    # Delete a specific secret from the user's secrets file
    secrets_file_path = f"data/{username}_secrets.txt"
    if os.path.exists(secrets_file_path):
        with open(secrets_file_path, "r") as secrets_file:
            lines = secrets_file.readlines()

        with open(secrets_file_path, "w") as secrets_file:
            for line in lines:
                decrypted_secret = decrypt_secret(line.strip().split(",")[0], line.strip().split(",")[1])
                if secret != decrypted_secret:
                    secrets_file.write(line)

# Delete a user account, move data to deleted users file, and remove the user's secrets file
def delete_user_account(username):
    # Open the users.txt file in read mode
    with open("data/users.txt", "r") as user_file:
        lines = user_file.readlines()

    # Open the users.txt file in write mode to update it
    with open("data/users.txt", "w") as user_file:
        for line in lines:
            data = line.strip().split(",")
            stored_username = data[0]
            
            if username != stored_username.lower():
                user_file.write(line)
    
    with open("data/deleted_users.txt", "a") as deleted_users_file:
        deleted_users_file.write(",".join(data) + "\n")
    user_folder_path = f"data/{username}_secrets.txt"

    if os.path.exists(user_folder_path):
        os.remove(user_folder_path)
        
# Register a new user and save their information
def register_user():
    print("\n" + "="*30)
    print("🚀 Welcome to the Secret Keeper App - Registration")
    username = input("Enter username: ")

    if check_duplicate_username(username.lower()):
        print("\n❌ Oops! That username is already taken. Please choose a different one.")
        return

    password = getpass.getpass("Enter password: ")
    while len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
        print("\n❌ Password should be at least 8 characters long and contain both letters and numbers.")
        password = getpass.getpass("Enter password: ")
        
    first_name = input("Enter your First Name: ")
    last_name = input("Enter your Last Name: ")
    age = input("Enter your Age: ")
    email = input("Enter your Email Address: ")

    salt = bcrypt.gensalt()
    password_hash = hash_password(password, salt)
    save_user_to_file(username, salt.decode('utf-8'), password_hash.decode('utf-8'), first_name, last_name, age, email)
    print("\n✅ Registration successful! You're now part of the Secret Keeper community. Keep your secrets safe!")

    print("\n🌟 Congratulations! Your secrets are now under the strongest protection. Let the secret-keeping begin!")

# Log in an existing user and validate their credentials
def login_user():
    print("\n" + "="*30)
    print("🔐 User Login")
    username = input("Enter username: ").lower()

    with open("data/users.txt", "r") as user_file:
        lines = user_file.readlines()
        for line in lines:
            data = line.strip().split(",")
            if len(data) == 7:
                stored_username, stored_salt, stored_password_hash, first_name, last_name, age, email = data
                if username == stored_username.lower():
                    entered_password = getpass.getpass("Enter password: ")

                    entered_password_hash = hash_password(entered_password, stored_salt).decode('utf-8')
                    if entered_password_hash == stored_password_hash:
                        print("\n" + "="*30)
                        print(f"🎉 Welcome back, {first_name}! Your secrets missed you.")
                        return username
                    else:
                        print("\n❌ Incorrect password. Login failed.")
                        return None

        print("\n❌ Oops! Username not found. Please check your credentials and try again.")
        return None

# Greet the user when they log in
def greet_user(first_name):
    if first_name.lower() != "user":
        print("\n" + "="*30)
        print(f"🎉 Welcome back, {first_name}! Time to unlock the secrets.")

# Bid farewell to the user when they log out
def farewell_user():
    print("\n" + "="*30)
    print("👋 Goodbye! Until next time. Keep those secrets safe!")

 # Display the user dashboard with options to manage secrets
def user_dashboard(username):
    print("\n" + "="*30)
    print("📜 User Dashboard")

    while True:
        print("\n1. View Secrets\n2. Add Secret\n3. Delete Secret\n4. Delete Account\n5. Logout")
        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            secrets = get_user_secrets(username)
            if secrets:
                print("\n🔒 Your Secrets:")
                for index, secret in enumerate(secrets, 1):
                    print(f"{index}. {secret.strip()}")
            else:
                print("\n❌ No secrets found. Your secrets are like stars – sometimes you can't see them, but you know they're always there.")

        elif choice == "2":
            secret = input("\nEnter the secret you want to add: ")
            key, encrypted_secret = encrypt_secret(secret)
            add_secret_to_file(username, key, encrypted_secret)
            print("\n✅ Secret added successfully! Your secret is now under the best encryption in town.")

        elif choice == "3":
            secrets = get_user_secrets(username)
            if secrets:
                print("\n🔒 Your Secrets:")
                for index, secret in enumerate(secrets, 1):
                    print(f"{index}. {secret.strip()}")

                choice = input("\nEnter the number of the secret you want to delete: ")
                try:
                    choice_index = int(choice) - 1
                    if 0 <= choice_index < len(secrets):
                        delete_secret_from_file(username, secrets[choice_index].strip())
                        print("\n✅ Secret deleted successfully! The secret is out – literally.")

                    else:
                        print("\n❌ Invalid choice. Please enter a valid number.")
                except ValueError:
                    print("\n❌ Invalid input. Please enter a number.")
            else:
                print("\n❌ No secrets found. Add some secrets and make your dashboard shine!")

        elif choice == "4":
            delete_user_account(username)
            print("\n✅ Account deleted successfully! It's like you were never here. Shhh...")
            farewell_user()
            break

        elif choice == "5":
            farewell_user()
            break

        else:
            print("\n❌ Invalid choice. Please enter a number between 1 and 5.")

# Main application loop
def main_application():
    initialize_project()
    print("\n" + "="*30)
    print("🚀 Welcome to the Secret Keeper App!")
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == "1":
            register_user()
        elif choice == "2":
            username = login_user()
            if username:
                greet_user("User")
                user_dashboard(username)
        elif choice == "3":
            farewell_user()
            break
        else:
            print("\n❌ Invalid choice. Please enter a number between 1 and 3.")

# RUN Main Application
main_application()
