import json
import sys
import os
import re 
import uuid
import time
import hashlib
import getpass
import socket, ssl
import threading
from cmd import Cmd
from os import urandom
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from os.path import exists as file_exist
from contextlib import closing

flag = False
stop_event = False
contact_list = []
Contact_list_from_file = ''
user_file = "user.json"
contact_file = "contact.json"
private_key_file = "private.key"
public_key_file = "public.pem"
pattern = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

# function that validate useremail address with regular express
def validate_email():
	# get user's email
	email = input("Enter Email Address: ")

	# validate email input using regular expression
	while not re.match(pattern, email):
		print("\nInvalid email address. Please try again.\n")
		email = input("Enter Email Address: ")	
	return email.lower()

# function that generate public and private key
def generate_RSA_key():
	key = RSA.generate(2048)
	private_key = key.export_key()
	file_out = open(private_key_file, "wb")
	file_out.write(private_key)
	file_out.close()

	public_key = key.publickey().export_key()
	file_out = open(public_key_file, "wb")
	file_out.write(public_key)
	file_out.close()

# function that encrypt file
def encrypt_textfile(input_textfile, output_textfile, receiver_public_key):
	data = open(input_textfile, "r").read().encode("utf-8")
	file_out = open(output_textfile, "wb")


	recipent_key = RSA.import_key(open(receiver_public_key).read())
	session_key = get_random_bytes(16)

	# Encrypt the session key with the public RSA key
	cipher_rsa = PKCS1_OAEP.new(recipent_key)
	enc_session_key = cipher_rsa.encrypt(session_key)


	# Encrypt the data with the AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(data)
	[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
	file_out.close()

# function that decrpyt file
def decrypt_textfile(input_textfile, output_textfile, sender_private_key):
	file_in = open(input_textfile, "rb")
	private_key = RSA.import_key(open(sender_private_key).read())
	enc_session_key, nonce, tag, ciphertext = \
		[ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
	file_in.close()

	# Decrypt the session key with the private RSA key
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)

	# Decrypt the data with the AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	data = cipher_aes.decrypt_and_verify(ciphertext,tag)
	file_out = open(output_textfile, "wb")
	file_out.write(data)
	file_out.close()
def write_contact_file():
	if file_exist(contact_file):
		# decrypt first
		decrypt_textfile(contact_file, contact_file, private_key_file)
		# write back to json file with non duplicate key
		with open(contact_file, "w") as write_json:
			json.dump(Contact_list_from_file, write_json)
		# Encrypt it
		encrypt_textfile(contact_file, contact_file, public_key_file)

def read_contact_file():
	global Contact_list_from_file
	if file_exist(contact_file):
		decrypt_textfile(contact_file, contact_file, private_key_file)
		Contact_list_from_file = json.load(open(contact_file, "r"))
		encrypt_textfile(contact_file, contact_file, public_key_file)

# function hash password value using sha356 with salt
def hash_data(password):
   # uuid is used to generate a random number of the specified password
   salt = uuid.uuid4().hex
   return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

# function that take password of user entered and compare with hashed value in database
def check_hashed_data(hashed_password, user_password):
   password, salt = hashed_password.split(':')
   return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

# Search thru contact file
def search_user(msg, Contact):
	for keyval in Contact:
		if msg.lower() == keyval["email"]:
			name = keyval["name"]
			return name

def search_email(msg, Contact):
	for keyval in Contact:
		if msg.lower() == keyval["email"]:
			email = keyval["email"]
			return email

def add_client_contact():
	global Contact_list_from_file
	# global stop_event
	# stop_event = True
	Duplicate = False
	name = input("Enter Full Name: ")
	email = validate_email()
	# dictionary
	contact = {
		"name": name,
		"email": email
	}
	# append contact.json everytime add new contact in
	contact_list.append(contact)
	if not file_exist(contact_file):
		with open(contact_file, "w") as f:
			# json.dump(list,f, indent=4)
			json.dump(contact_list,f, indent=4)
		encrypt_textfile(contact_file, contact_file, public_key_file)
		Contact_list_from_file = contact_list
	else:
		# decrypt the contact.json file so system can access
		read_contact_file()
		Contact_list_from_file.append(contact)
		# remove duplicate contact
		unique_entries = []

		for entry in Contact_list_from_file:
			if entry not in unique_entries:
				unique_entries.append(entry)
			else: 
				Duplicate = True

		Contact_list_from_file = unique_entries
		write_contact_file()
	# tell user that contact have been added
	if Duplicate:
		print("Duplicate contact, nothing added")
	else:
		print("Contact added")

# TCP client that send info to server and listen 
def TCP_client(email):
	while True:
		global Contact_list_from_file
		# message for handshake server and client
		handshake_msg = "yes"
		# create a socket object
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# get local machine name
		host = socket.gethostname()                           

		port = 9999

		while True:
		# try to connect to the server
			try:
				# keep connecting, if fail goes to exception, if succed break the loop
				client_socket.connect((host, port))
				break
			except:
			# if the connection fails, wait and try again
				time.sleep(1)
				
		# Wrap the socket in an SSL layer
		context = ssl.create_default_context()
		context.verify_mode = ssl.CERT_REQUIRED
		context.check_hostname = True
		context.load_verify_locations('cert.pem')	
		client_socket = context.wrap_socket(client_socket, server_hostname='localhost')

		# send email address to server
		client_socket.send(email.encode("utf-8"))
		# Receive no more than 1024 bytes
		incoming_msg = client_socket.recv(1024)
		incoming_msg_str = incoming_msg.decode("utf-8")
		# print("incoming_email_str is " + incoming_email_str)

		if(incoming_msg_str != "no"): #if msg is 'sendrequest', skip this block
			# open contact file
			# search incoming email with existing email in contact list
			contact_email_client = search_email(incoming_msg_str, Contact_list_from_file)
			if contact_email_client == incoming_msg_str:
				client_socket.send(handshake_msg.encode("utf-8"))

		# File transfer receiving modules
		if(incoming_msg_str == "sendrequest"):
			
			contactemail = client_socket.recv(1024) #recieve identity of sender and filename
			contactemail_str = contactemail.decode("utf-8")
			filename = client_socket.recv(1024)
			filename_str = filename.decode("utf-8")
			filesize = client_socket.recv(1024)
			filesize_str = filesize.decode("utf-8")
			print("\nContact <" + contactemail_str + "> would like to send you <" + filename_str + ">\n--> Accept? y/n: ", end='', flush = True) #accept file
			fileAccept = input()
			if fileAccept == "y":
				client_socket.send(fileAccept.encode("utf-8")) #send acceptance/refusal
				with open(filename_str, "wb") as file:
					c = 0
					while c <= int(filesize_str):
						data = client_socket.recv(1024)
						if not (data):
							break
						file.write(data)
						c += len(data)
				print(filename_str + " successfully written.")
			else:
				msg = "n"
				client_socket.send(msg.encode("utf-8")) #send acceptance/refusal
		client_socket.close()
		time.sleep(5)

# TCP server than get online user that have added into contact list
def list_all_online_contact(email):
	connect = False

	msg = "no"
	# create a socket object
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	# get local machine name
	host = socket.gethostname()

	port = 9999

	# bind to the port
	try:
		serversocket.bind((host, port))                                   
	except OSError:
		print("port: " + str(port) + " uses by other client, try again!")
		return False
	# queue up to 5 requests
	serversocket.listen(5)    

	# Wrap the socket in an SSL context
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile='cert.pem', keyfile='cert.pem')


	# Set a timeout for the accept() method
	Wait_time = 3
	serversocket.settimeout(Wait_time)     
	# Continuously accept connections and handle them until a timeout occurs
	while True:
		try:
			# establish a connection
			client_socket,addr = serversocket.accept()

			# wrap the socket in an ssl layer
			clientsocket = context.wrap_socket(client_socket, server_side=True)

			# receiving email from other client
			client_message = clientsocket.recv(1024)
			client_msg_email_str = client_message.decode("utf-8")
			# search client email within contact file
			contact_email = search_email(client_msg_email_str, Contact_list_from_file)
			contact_name = search_user(client_msg_email_str, Contact_list_from_file)
			# if client email exist then send server email back
			if contact_email == client_msg_email_str:
				clientsocket.send(email.encode("utf-8"))
				# receiving another message on handshake whether 
				# both client have added each other contact
				client_handshake = clientsocket.recv(1024)
				client_handshake_str = client_handshake.decode("utf-8")
				if client_handshake_str == "yes":
					print("* " + contact_name +  " <" + contact_email + ">")
					connect = True
			else:
				clientsocket.send(msg.encode("utf-8"))
			clientsocket.close()
		except socket.timeout:
			break
	serversocket.close()
	return connect

def send_file(recipient_email, filename, email): #send file with arguments being file recipient, file, user_email
	connect = False

	msg = "no"
	sendmsg = "sendrequest"
	# create a socket object
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	# get local machine name
	host = socket.gethostname()                           

	port = 9999

	# bind to the port
	try:
		serversocket.bind((host, port))
	except OSError:
		print("port: " + str(port) + " in use by other client, try again!")
		return False
	
	# queue up to 5 requests
	serversocket.listen(5)       

	# Wrap the socket in an SSL context
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	context.load_cert_chain(certfile='cert.pem', keyfile='cert.pem')

	# file_size
	if file_exist(filename):
		file_size = os.path.getsize(filename)
	else:
		print("File does not exist, please check file path")
		return
	# Set a timeout for the accept() method
	Wait_time = 3
	serversocket.settimeout(Wait_time) 
	# Continuously accept connections and handle them until a timeout occurs
	while True:
		try:
			# establish a connection
			client_socket,addr = serversocket.accept()
			# wrap the socket in an ssl layer
			clientsocket = context.wrap_socket(client_socket, server_side=True)

			# receiving email from other client
			client_message = clientsocket.recv(1024)
			client_msg_email_str = client_message.decode("utf-8")

			if(recipient_email == client_msg_email_str): #if email sent by client is recipient email
				connect = True
				clientsocket.send(sendmsg.encode("utf-8")) #send request to send a file
				clientsocket.send(email.encode())
				clientsocket.send(filename.encode()) #additionally send identity and filename
				clientsocket.send(str(file_size).encode())

				ready_to_accept = clientsocket.recv(1024) #receive acceptance/refusal from client
				ready_to_accept_str = ready_to_accept.decode("utf-8")
				
				# read data and send data byte by byte
				if ready_to_accept_str == "y":
					with open(filename, "rb") as file:
						c = 0
						while c <= file_size:
							data = file.read(1024)
							if not (data):
								break
							clientsocket.sendall(data)
							c += len(data)
					print("answer was yes, file has been sent")
				else:
					print("Reciever refuse to accpet file")
			clientsocket.close()
		except socket.timeout:
			break
	serversocket.close()
	return connect
