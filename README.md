# **SecureDrop**

## **Overview**
SecureDrop is a secure file-sharing application designed to prioritize user confidentiality and data integrity. This system allows users to register, authenticate, and exchange encrypted files with their contacts securely. Key features include user authentication, encrypted communication, and contact management.

---

## **Features**
- **User Registration & Authentication**:
  - Secure registration using hashed passwords.
  - Encrypted storage of user credentials and emails.
  - User login with validation against hashed data.

- **Contact Management**:
  - Add and manage contact lists.
  - Detect online contacts in real-time using TCP connections.

- **File Encryption & Decryption**:
  - RSA encryption for secure key exchange.
  - AES encryption for file content protection.

- **Secure Communication**:
  - Encrypted file sharing between authenticated users.
  - Real-time status of contacts using a client-server model.

---

## **Setup Instructions**
### **Prerequisites**
1. Ensure Python 3.x is installed on your system.
2. Install the required Python libraries:
   ```bash
   pip install pycryptodome
- Follow the prompts for registration or login.
### **Files Overview**
- `main.py`: Main program logic for user registration, authentication, and shell interface.
- `Helper.py`: Utility functions for encryption, validation, and network operations.
- `user.json`: Stores encrypted user credentials.
- `contact.json`: Stores encrypted contact lists.
- `private.key` and `public.pem`: RSA private and public keys for encryption.

### **Running the Program**
1. Start the application:
   ```bash
   python main.py
 ## **Key Functionalities**
- **Register a New User**:
  - Enter your full name, email, and password during registration.
  - Passwords and emails are hashed and stored securely.
- **Add a New Contact**:
  - Use the `add` command in the SecureDrop shell to add contacts.
- **List Online Contacts**:
  - Use the `list` command to view contacts currently online.
- **Send Files**:
  - Use the `send` command to securely transfer a file to a contact.  
    - You will be prompted to:
      1. Enter the recipient's email address.
      2. Provide the file name from your current directory.  
    - If the recipient accepts, the file will be securely transferred using SSL encryption.
- **Exit the Program**:
  - Use the `exit` command to safely encrypt and save your data before exiting.

---

## **Commands in SecureDrop Shell**
- `add`: Add a new contact to your list.
- `list`: Display all online contacts from your contact list.
- `send`: Securely transfer a file to a contact.
- `exit`: Safely log out and encrypt sensitive data.

---

## **Security Notes**
- Passwords and emails are hashed using SHA-256 with unique salts.
- Files are encrypted using a combination of RSA and AES encryption.
- Sensitive data (e.g., contact lists) is encrypted before storage.

---

## **Contact**
For further questions or feature requests, please contact:  
**Noah Fay**  
noahfay43@gmail.com

---
