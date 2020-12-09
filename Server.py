# Python program to implement server side of chat room.  
import socket  
import select  
import sys  
from thread import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
#from cryptography import x509
import os

"""The first argument AF_INET is the address domain of the  
socket. This is used when we have an Internet Domain with  
any two hosts The second argument is the type of socket.  
SOCK_STREAM means that data or characters are read in  
a continuous flow."""
#DUDE -> Add MTLS Secure SOCKET Creation. 
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
  
#2b. DH Key Exchange -> shared_key
#If DH key doesn't exist, generate

if not os.path.exists("./Certs/server_public_key.pem"):
    #Generate DC Public and Private Key for Key Exchange
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()

    server_public_key_pem = server_public_key.public_bytes( encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo )
    server_private_key_pem = server_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'testpassword'))

    if not os.path.exists("./Certs"):
        os.mkdir("./Certs")
    print "HERE?"
    open("./Certs/server_public_key.pem","w").write(server_public_key_pem)
    open("./Certs/server_private_key.key","w").write(server_private_key_pem)
else:
    
    server_public_key_pem = open("./Certs/server_public_key.pem","r").read()
    server_private_key_pem = open("./Certs/server_private_key.key","r").read()

    server_public_key = load_pem_public_key(server_public_key_pem,backend=default_backend())
    server_private_key = load_pem_private_key(server_private_key_pem, password=b'testpassword')
    print "Over HERE: ", server_private_key


print server_public_key
print server_private_key
#Else load

list_of_clients = []  
  
def clientthread(conn, name):  
  
    # sends a message to the client whose user object is conn  
    conn.send("Welcome to this chatroom!")  
  
    while True:  
            try:  
                message = conn.recv(2048)  
                #4. AES Decryption using shared key
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
                #5. AES Encryption w shared_key for client
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
  
    client_name = conn.recv(2048)  
    client_pubKey = conn.recv(2048)  
    print (client_name + " pub key: "+ client_pubKey) 
 
    server_public_key_pem = server_public_key.public_bytes( encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo )
    print ("Servers Pub key: ", server_public_key_pem) 
    print ("Servers Pub key Obj: ", load_pem_public_key(server_public_key_pem))
    conn.send(server_public_key_pem)

    #print (client_public_key)

    """Maintains a list of clients for ease of broadcasting  
    a message to all available people in the chatroom"""
    list_of_clients.append(conn)  
  
    # prints the address of the user that just connected  
    print (client_name + " connected") 
  
    # creates and individual thread for every user  
    # that connects  
    start_new_thread(clientthread,(conn,client_name))    
  
conn.close()  
server.close()  