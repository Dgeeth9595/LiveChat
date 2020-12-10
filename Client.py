from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Python program to implement client side of chat room.  
import socket  
import select  
import sys  
import os
import json
from base64 import b64encode
from base64 import b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
#if len(sys.argv) != 3:  
#    print ("Correct usage: script, IP address, port number") 
#    exit()  
#IP_address = str(sys.argv[1])  
#Port = int(sys.argv[2])  
IP_address = "127.0.0.1"
Port = 8777

server.connect((IP_address, Port))  
name = raw_input("Name: ")
server.send(name)

#####-----1. Generate Client RSA Keys-----#####
client_rsa_private_key = rsa.generate_private_key( public_exponent=65537, key_size=4096, backend=default_backend())
client_rsa_public_key = client_rsa_private_key.public_key()
#####-----1. Generate Client RSA Keys-----#####


#####-----2. Exchange RSA Pub Key-----#####
# Client Pub Key Obj -> Client Pub Key PEM
client_rsa_public_key_pem = client_rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
# Recieve Server Pub Key PEM
server_rsa_public_key_pem = server.recv(2048)

# Send Client Pub Key PEM
server.send(client_rsa_public_key_pem)

# Server Pub Key PEM -> Server Pub Key Obj
server_rsa_public_key = load_pem_public_key(server_rsa_public_key_pem, backend=default_backend())
#####-----2. Exchange RSA Pub Key-----#####


#####-----3. Decrypt Clients DH Keys with Clients RSA Priv Key-----#####
# Recieve encrypted enc_client_dh_pub_key_pem and enc_client_dh_private_key_pem
enc_client_dh_pub_key_pem = server.recv(2048) 
server.send("Recieved")
enc_client_dh_private_key_pem = server.recv(2048) 

# Decrypt encrypted enc_client_dh_pub_key_pem and enc_client_dh_private_key_pem with client_rsa_private_key
client_dh_pub_key_pem = client_rsa_private_key.decrypt(enc_client_dh_pub_key_pem,padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
client_dh_private_key_pem = client_rsa_private_key.decrypt(enc_client_dh_private_key_pem,padding.OAEP( mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))

# Load DH PEM Keys as DH Key Obj
client_dh_pub_key = load_pem_public_key(client_dh_pub_key_pem, backend=default_backend())
client_dh_private_key = load_pem_private_key(client_dh_private_key_pem, password=b'testpassword', backend=default_backend())
#####-----3. Decrypt Clients DH Keys with Clients RSA Priv Key-----#####


#####-----4. Recieve Servers Pub DH Key -----#####
# Recieve server_dh_pub_key_pem
server_dh_pub_key_pem = server.recv(2048)

# Convert server_dh_pub_key_pem -> server_dh_pub_key
server_dh_pub_key = load_pem_public_key(server_dh_pub_key_pem, backend=default_backend())
#####-----4. Recieve Servers Pub DH Key -----#####


#####-----5. Generate DH Shared Key with Clients Priv DH Key + Servers Pub DH Key-----#####
client_shared_key = client_dh_private_key.exchange(server_dh_pub_key)
server.send("Done")
#####-----5. Generate DH Shared Key with Clients Priv DH Key + Servers Pub DH Key-----#####


while True:  
  
    # maintains a list of possible input streams  
    sockets_list = [sys.stdin, server]  
  
    """ There are two possible input situations. Either the  
    user wants to give manual input to send to other people,  
    or the server is sending a message to be printed on the  
    screen. Select returns from sockets_list, the stream that  
    is reader for input. So for example, if the server wants  
    to send a message, then the if condition will hold true  
    below.If the user wants to send a message, the else  
    condition will evaluate as true"""
    read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])  
  
    for socks in read_sockets:  
        if socks == server:  
            ciphertext = socks.recv(2048)  
            #####-----7. DECRYPT MSG-----#####
            b64 = json.loads(ciphertext)
            json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
            jv = {k:b64decode(b64[k]) for k in json_k}

            cipher = AES.new(client_shared_key[:16], AES.MODE_OCB, nonce=jv['nonce'])
            cipher.update(jv['header'])
            message = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            print message
            #####-----7. DECRYPT MSG-----#####
        else:  
            message = sys.stdin.readline()  

            #####-----6. ENCRYPT MSG-----#####
            header = b"header"
            cipher = AES.new(client_shared_key[:16], AES.MODE_OCB)
            cipher.update(header)
            ciphertext, tag = cipher.encrypt_and_digest(message)

            json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
            json_v = [ b64encode(x).decode('utf-8') for x in cipher.nonce, header, ciphertext, tag ]
            enc_result = json.dumps(dict(zip(json_k, json_v)))
            server.send(enc_result)
            #####-----6. ENCRYPT MSG-----#####

            #server.send(message)  
            sys.stdout.write("You: ")  
            sys.stdout.write(message)  
            sys.stdout.flush()  
server.close()