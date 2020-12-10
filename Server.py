from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Python program to implement server side of chat room.  
import socket  
import select  
import sys  
from thread import *
  
"""The first argument AF_INET is the address domain of the  
socket. This is used when we have an Internet Domain with  
any two hosts The second argument is the type of socket.  
SOCK_STREAM means that data or characters are read in  
a continuous flow."""
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
  
# checks whether sufficient arguments have been provided  
#if len(sys.argv) != 3:  
#    print ("Correct usage: script, IP address, port number") 
#    exit()  
  
# takes the first argument from command prompt as IP address  
#IP_address = str(sys.argv[1])  
IP_address = "127.0.0.1"

# takes second argument from command prompt as port number  
#Port = int(sys.argv[2])  
Port = 8777 
"""  
binds the server to an entered IP address and at the  
specified port number.  
The client must be aware of these parameters  
"""
server.bind((IP_address, Port))  
  
"""  
listens for 100 active connections. This number can be  
increased as per convenience.  
"""
server.listen(100)  
  
list_of_clients = {}  

#####-----1. Generate Server RSA Keys-----#####
server_rsa_private_key = rsa.generate_private_key( public_exponent=65537, key_size=4096, backend=default_backend())
server_rsa_public_key = server_rsa_private_key.public_key()
#####-----1. Generate Server RSA Keys-----#####

#####-----2. Generate Server DH Keys-----#####
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

server_dh_private_key = parameters.generate_private_key()
server_dh_pub_key = server_dh_private_key.public_key()
#####-----2. Generate Server DH Keys-----#####
  
def clientthread(conn, name, shared_key):  
  
    # sends a message to the client whose user object is conn  
    conn.send("Welcome to this chatroom!")  
  
    while True:  
            try:  
                message = conn.recv(2048)  
                #####-----9. DECRYPT MSG-----#####

                #####-----9. DECRYPT MSG-----#####
                if message:  
  
                    """prints the message and address of the  
                    user who just sent the message on the server  
                    terminal"""
                    print (name + ": " + message)  
  
                    # Calls broadcast function to send message to all  
                    message_to_send = name + ": " + message  
                    broadcast(message_to_send, conn)  
  
                else:  
                    """message may have no content if the connection  
                    is broken, in this case we remove the connection"""
                    remove(conn)  
  
            except:  
                continue
  
"""Using the below function, we broadcast the message to all  
clients who's object is not the same as the one sending  
the message """
def broadcast(message, connection):  
    for clients in list_of_clients:  
        if clients!=connection:  
            try:  
                #####-----10. ENCRYPT MSG-----#####
                print "Shared Key: ", list_of_clients[clients]
                #####-----10. ENCRYPT MSG-----#####
                clients.send(message)  
            except:  
                clients.close()  
  
                # if the link is broken, we remove the client  
                remove(clients)  
  
"""The following function simply removes the object  
from the list that was created at the beginning of  
the program"""
def remove(connection):  
    if connection in list_of_clients:  
        list_of_clients.remove(connection)  
  
while True:  
  
    """Accepts a connection request and stores two parameters,  
    conn which is a socket object for that user, and addr  
    which contains the IP address of the client that just  
    connected"""
    conn, addr = server.accept()  
  
    # save name
    name = conn.recv(2048)  

    #####-----3. Exchange RSA Pub Key-----#####
    # Server Pub Key Obj -> Server Pub Key PEM
    server_rsa_public_key_pem = server_rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Send Server Pub Key PEM
    conn.send(server_rsa_public_key_pem)

    # Recieve Client Pub Key PEM
    client_rsa_public_key_pem = conn.recv(2048)
 
    # Client Pub Key PEM -> Client Pub Key Obj
    client_rsa_public_key = load_pem_public_key(client_rsa_public_key_pem, backend=default_backend())
    #####-----3. Exchange RSA Pub Key-----#####


    #####-----4. Generate Clients DH Keys-----#####
    client_dh_private_key = parameters.generate_private_key()
    client_dh_pub_key = client_dh_private_key.public_key()
    #####-----4. Generate Clients DH Keys-----#####


    #####-----5. Encrypt Clients DH Keys with Clients RSA Pub Key-----#####
    # client_dh_pub_key -> client_dh_pub_key_pem
    client_dh_pub_key_pem = client_dh_pub_key.public_bytes( encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo )
    # client_dh_priv_key -> client_dh_priv_key_pem
    client_dh_private_key_pem = client_dh_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'testpassword'))

    # encrypt client_dh_pub_key & client_dh_priv_key_pem with client_rsa_public_key_pem
    enc_client_dh_pub_key_pem = client_rsa_public_key.encrypt(client_dh_pub_key_pem, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
    enc_client_dh_private_key_pem = client_rsa_public_key.encrypt(client_dh_private_key_pem, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
    #####-----5. Encrypt Clients DH Keys with Clients RSA Pub Key-----#####


    #####-----6. Send Clients Encrypted DH Keys-----#####
    conn.send(enc_client_dh_pub_key_pem)
    rec = conn.recv(2048)
    conn.send(enc_client_dh_private_key_pem)
    #####-----6. Send Clients Encrpyted DH Keys-----#####

    
    #####-----7. Send Servers Pub DH Keys-----#####
    # server_dh_pub_key -> server_dh_pub_key_pem
    server_dh_pub_key_pem = server_dh_pub_key.public_bytes( encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo )
    
    # send server_dh_pub_key_pem
    conn.send(server_dh_pub_key_pem)
    #####-----7. Send Servers Pub DH Keys-----#####

    
    #####-----8. Generate DH Shared Key with Servers Priv DH Key + Clients Pub DH Key-----#####
    shared_key = server_dh_private_key.exchange(client_dh_pub_key)
    done = conn.recv(2048)
    #####-----8. Generate DH Shared Key with Servers Priv DH Key + Clients Pub DH Key-----#####

    """Maintains a list of clients for ease of broadcasting  
    a message to all available people in the chatroom"""
    list_of_clients[conn] = shared_key  
  
    # prints the address of the user that just connected  
    print (name + " connected") 
  
    # creates and individual thread for every user  
    # that connects  
    start_new_thread(clientthread,(conn,name,shared_key))    
  
conn.close()  
server.close()  