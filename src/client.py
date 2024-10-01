# Client Code
import asyncio
import base64
import json
import os
import websockets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol import generate_keys ,verify_signature

clients = []
counter = 0
last_counters = 0  # Dictionary to track last known counters for each user

async def send_hello(websocket,private_key,public_pem):
    message = {
        "type": "signed_data",
        "data": {
            "type": "hello",
            "public_key": public_pem.decode('utf-8')
        },
        "counter": counter + 1,  # Increment counter appropriately
        "signature": ""  # Placeholder for signature
    }
    last_counters == counter + 1
    # Sign the message
    data_json = json.dumps(message['data'])
    message_to_sign = f"{data_json}{message['counter']}".encode('utf-8')
    signature = private_key.sign(
        message_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    message["signature"] = base64.b64encode(signature).decode('utf-8')
    print(json.dumps(message))
    await websocket.send(json.dumps(message))
    print("send hello message to server")

async def request_client_list(websocket):
    request_message = {
        "type": "client_list_request"
    }
    await websocket.send(json.dumps(request_message))

    response = await websocket.recv()
    try:
        client_list_data = json.loads(response)
        print("Received client list data:", client_list_data)
        if 'servers' in client_list_data:
            print("Connected clients:")
            
            for server in client_list_data['servers']:
                print(f"Server: {server['address']}")
                for client in server['clients']:
                    print(f"  Client Public Key: {client}")
                    clients.append((server['address'], client))  # Store address and client public key
            return clients
        else:
            print("Received response does not contain 'servers'")
            return []
    except json.JSONDecodeError:
            print("Failed to decode JSON from server response.")
    except Exception as e:
        print(f"Error processing server response: {e}")

async def send_public_chat(websocket,fingerprint):
    print("Connected to server!")  # Log connection
    user_message = input("Enter your public chat message: ")
    public_chat_message = {
        "data": {
            "type": "public_chat",
            "sender": fingerprint,  # Use the fingerprint that you computed before
            "message": user_message
        }
    }
    print(json.dumps(public_chat_message))
    await websocket.send(json.dumps(public_chat_message))
    print("Public message sent!")

async def send_chat_message(websocket,private_key,public_pem, message_content, destination_server, recipient_public_key_pem):
    # Generate AES key for encryption
    # aes_key = os.urandom(32)  # AES 256 key
    aes_key = b'\xc0hY\x99\xc2\xa4\x96\x98I\xdc\x1c\xa1\xcd\x9e\x8e6\xab\xab.d\rk\xccy\xb5\xfa\xd0D\x08f \x8c' # fixed AES key
    # iv = os.urandom(12)  # GCM requires a 12-byte IV
    iv = b'fixedivforaesgcm' # FIXED iv

    # Encrypt the message using AES GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_content.encode('utf-8')) + encryptor.finalize()
    auth_tag = encryptor.tag  # Get authentication tag

    # Encrypt the AES key with the recipient's public RSA key
    recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode('utf-8'))
    encrypted_symm_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Construct the chat message
    chat_message = {
        "type": "signed_data",
        "data": {
            "type": "chat",
            "destination_servers": [destination_server],
            "iv": base64.b64encode(iv).decode('utf-8'),  # Base64 encode the IV
            "symm_keys": [base64.b64encode(encrypted_symm_key).decode('utf-8')],  # Base64 encode encrypted AES key
            "chat": base64.b64encode(ciphertext).decode('utf-8'),  # Base64 encode ciphertext
            "auth_tag": base64.b64encode(auth_tag).decode('utf-8')  # Base64 encode auth tag
        },
        "counter": counter + 1 ,  # Increment the counter for each message
        "signature": ""  # Placeholder for signature
    }
    
    # Sign the chat message
    data_json = json.dumps(chat_message["data"])
    message_to_sign = f"{data_json}{chat_message['counter']}".encode('utf-8')
    signature = private_key.sign(
        message_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32  # Fixed salt length specified
        ),
        hashes.SHA256()
    )
    chat_message["signature"] = base64.b64encode(signature).decode('utf-8')
    last_counters == counter +1
    # Send the chat message
    await websocket.send(json.dumps(chat_message))
    print(f"Sent message: {chat_message}") 
    print(f"[Private Chat] {message_content}")
    

async def receive_messages(websocket,private_key,public_pem):
     while True:
        try:
            response = await websocket.recv()
            print(f"Raw response: {response}")  # Debugging output
            message_data = json.loads(response)
            print(f"Received message: {message_data}")

            if message_data.get('type') == 'signed_data':
                data_json = json.dumps(message_data['data'])
                signature = message_data['signature']
                counter = message_data['counter']

                # reject if the new counter is not greater than the last received.
                if counter <= last_counters:
                    print("Message rejected due to replay attack.")
                    return
                
                # Validate the signature
                sender_public_key_pem = message_data['data'].get('sender_public_key')
                if sender_public_key_pem is not None:
                    sender_public_key = serialization.load_pem_public_key(sender_public_key_pem.encode('utf-8'))
                    
                    if not verify_signature(sender_public_key, data_json, signature):
                        print("Received message with invalid signature!")
                        return
                
                # Handle public chat messages
                if message_data['data']['type'] == 'public_chat':
                    sender = message_data['data']['sender']
                    message = message_data['data']['message']
                    print(f"[Public Chat] {sender}: {message}")
                
                # Handle chat messages meant for this client
                if message_data['data']['type'] == 'chat':
                    print("chat")
                    encrypted_symm_key = base64.b64decode(message_data['data']['symm_keys'][0])
                    try:
                        aes_key = private_key.decrypt(
                            encrypted_symm_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        iv = base64.b64decode(message_data['data']['iv'])
                        ciphertext = base64.b64decode(message_data['data']['chat'])
                        auth_tag = base64.b64decode(message_data['data']['auth_tag'])
                        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag))
                        decryptor = cipher.decryptor()
                        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                        print(f"[Private Chat] {plaintext.decode('utf-8')}")

                    except Exception as e:
                        print(f"Decryption failed: {e}")
        except asyncio.TimeoutError:
            print("Timeout: No messages received within the last 5 seconds.")
            continue  # Continue to wait for more messages
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

async def send_messages(ws,private_key,public_pem,fingerprint):
    while True:
            print("Choose an option:")
            print("1. Send a Private Chat")
            print("2. Public Chat")
            print("3. Request Client List")
            print("4. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                print("Connected Clients:")
                for index, (server_address, client_public_key) in enumerate(clients):
                    print(f"{index + 1}. Server: {server_address}, Client Public Key: {client_public_key}")
                
                recipient_index = int(input("Select recipient (number): ")) - 1
                if 0 <= recipient_index < len(clients):
                    recipient_public_key_pem = clients[recipient_index][1]  # Get the public key
                    destination_server = clients[recipient_index][0]  # Get the address of the recipient's server
                    message_content = input("Enter your message: ")
                    await send_chat_message(ws,private_key,public_pem, message_content, destination_server, recipient_public_key_pem)
                else:
                    print("Invalid selection. Please try again.")

            elif choice == "2":
                await send_public_chat(ws,fingerprint)

            elif choice == "3":
                await request_client_list(ws)

            elif choice == "4":
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please try again.")

async def client_session(uri):
    async with websockets.connect(uri) as websocket:
        print("Connected to server")
        private_key, public_pem, fingerprint = generate_keys()
        await send_hello(websocket,private_key,public_pem)
        await request_client_list(websocket)
        while True:
            if not await send_messages(websocket,private_key,public_pem,fingerprint):
                break
            if not await receive_messages(websocket,private_key,public_pem):
                break

async def client_main():
    uri = "ws://localhost:8765"
    while True:
        try:
            await client_session(uri)
        except ConnectionRefusedError:
            print("Failed to connect to the server. Retrying in 5 seconds...")
            await asyncio.sleep(5)
        else:
            break

# Run the client main function in the event loop
if __name__ == "__main__":
    asyncio.run(client_main())