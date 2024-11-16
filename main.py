import Helper
import json
import threading
import sys
import getpass
from cmd import Cmd
from os.path import exists as file_exist

User_email = " " 

def main():
	# check if client have been registered
	# using private key to check
	if not file_exist(Helper.private_key_file) and not file_exist(Helper.public_key_file):
		print("No users are registered with this client.")
		# ask user to register
		answer = input("Do you want to register a new user (y/n)? ")
		if answer == "y" or answer == "Y":
			# register a new user
			register()
		else:
			# exit
			sys.exit(0)
	login()
		
def register():
	# get username
	username = input("Enter Full Name: ")
	# call fuction to take email and validate
	email = Helper.validate_email()
	# get user's password
	password = getpass.getpass("Enter password: ")
	# get user's password again
	password2 = getpass.getpass("Re-enter password: ")

	# check if password match
	if password != password2:
		print("Password doesn't match")
		# go back to register()
		register()
	else:
		print("\nPassword match")
		# hash the password
		hashed_username = Helper.hash_data(username.lower())
		hashed_password = Helper.hash_data(password)
		hashed_email = Helper.hash_data(email)
		# save user's information to a file
		# create a dictionary
		user = {
			"username": hashed_username,
			"email": hashed_email,
			"password": hashed_password
		}
		# save to a file
		with open(Helper.user_file, "w") as f:
			json.dump(user, f, indent=2)

		# generate private_key && public
		Helper.generate_RSA_key()
		# complete user registerd and exit the program
		print("User Registered.")
		print("Exiting SecureDrop")
		sys.exit(0)
	
def login():
	try:
		global User_email
		#ask user for email, password
		loginEmail = Helper.validate_email()
		User_email = loginEmail
		loginPass = getpass.getpass("Enter Password: ")
		#opens user.json to compare values, not sure if better way to do this
		Userinfo = json.load(open(Helper.user_file, "r"))
		#checks login info against user.json info
		if Helper.check_hashed_data(Userinfo["email"], loginEmail) and Helper.check_hashed_data(Userinfo["password"], loginPass):
			print("\n\nAuthentication successful, Welcome to SecureDrop")
			# decrypt the contact.json file so system can access
			Helper.read_contact_file()
			startShell()
		else: 
			print("\n\nAuthentication failed, try again")
			login()
	except: ValueError
	

#securedrop shell for once login goes through
def startShell():
	try:
		Thread_flag = True
		print("\n\nWelcome to SecureDrop, type 'help' for command list.")
		while True:
			# running thread only contact file is exist, and no thread is running yet
			if file_exist(Helper.contact_file) and Thread_flag:
				threadClient = threading.Thread(target=Helper.TCP_client, args=(User_email,), daemon=True)
				threadClient.start()
				Thread_flag = False

			# user input for command
			user_input = input("SecureDrop>> ")
			## "add" - add new contact
			if user_input == "add":
				Helper.add_client_contact()
			# "list" - list all user online
			elif user_input == "list":
				print("\nThe following contacts are online:")
				if not Helper.list_all_online_contact(User_email):
					print("\nNo contact online")
			elif user_input == "send":
				print("input email of recipient ")
				arg1 = Helper.validate_email()
				arg2 = input("input file name in current directory to be sent: ")
				if not Helper.send_file(arg1, arg2, User_email):
					print("\nNo contact online")
			# "help" - list all command to user
			elif user_input == "help":
				print("add -> Add a new contact")
				print("list -> List all online contacts")
				print("send -> Transfer file to contact")
				print("exit -> Exit SecureDrop")
			# "exit" - break out of the program
			elif user_input == "exit":
				Helper.write_contact_file()
				print("Goodbye.")
				break
			# if no command enter correctly let user know
			else:
				print("invalid command")
	except KeyboardInterrupt:
		Helper.write_contact_file()

if  __name__  == '__main__': 
	main()

