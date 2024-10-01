import asyncio
import json
import websockets

# Represents the neighborhood of servers, initially with just itself
neighborhood_servers = {}

# Store local connected clients' public keys
connected_clients = {}

# Store mapping of server address to their connected clients
clients_from_neighborhood = {}

async def handler(websocket, path):
    print("Client connected.")
    try:
        async for message in websocket:
            data = json.loads(message)
            print(data)
            if 'data' in data:
                    # Handle any chat messages
                if data['data']['type'] == 'public_chat':
                    # Function to broadcast messages to all connected clients """
                    for client_key in connected_clients.keys():
                        client_websocket = connected_clients[client_key]
                        print(message)
                        await client_websocket.send(message)
                
                elif data['data']['type'] == 'hello':
                    public_key = data['data']['public_key']
                    connected_clients[public_key] = websocket
                    await broadcast_client_update()  # Notify other servers of the new client

                # Handle any chat messages
                elif data['data']['type'] == 'chat':
                    await handle_chat_message(websocket,data)

            # Handle client update requests from other servers
            elif data['type'] == 'client_list_request':
                # Prepare the response with all known client information
                response = {
                    "type": "client_list",
                    "servers": [
                        {
                            "address": "localhost:8765",
                            "clients": list(connected_clients.keys())
                        }
                    ] + [
                        {"address": server_info["address"], "clients": server_info["clients"]}
                        for server_info in clients_from_neighborhood.values()
                    ]
                }
                await websocket.send(json.dumps(response))
                print("sent")

            # Handle server hello from other servers
            elif data['type'] == 'server_hello':
                server_address = data['data']['sender']
                await register_server(server_address)

            elif data['type'] == 'client_update':
                # Store clients data from neighborhood servers
                sender_address = data.get("sender")
                if sender_address:
                    clients_from_neighborhood[sender_address] = {
                        "address": sender_address,
                        "clients": data["clients"]
                    }

    except websockets.exceptions.ConnectionClosed:
        # Remove the client if the connection is lost
        await handle_client_disconnect(websocket)

async def handle_client_disconnect(websocket):
    # print("disconnect")
    # Remove the client from the connected clients dictionary
    disconnected_client_key = [key for key, value in connected_clients.items() if value == websocket]
    if disconnected_client_key:
        del connected_clients[disconnected_client_key[0]]
        await broadcast_client_update()  # Inform other servers about the update

async def register_server(server_address):
    if server_address not in neighborhood_servers:
        neighborhood_servers[server_address] = server_address
        print(f"Added new server to neighborhood: {server_address}")

async def handle_chat_message(websocket, message_data):
    print(message_data)  # Print the entire message for debugging
    destination_servers = message_data['data']['destination_servers']

    if not destination_servers:
        print("No destination servers found.")
        return  # Exit if no destination servers are specified

    extracted_server = destination_servers[0]  # Get the first destination server
    print("Extracted server:", extracted_server)

    if extracted_server == "localhost:8765":
        print("Sending back to the same server")
        await websocket.send(json.dumps(message_data))  # Serialize and send back the message
    else:
        print("Connecting to another server:", extracted_server)
        try:
            async with websockets.connect(extracted_server) as server_ws:
                await server_ws.send(json.dumps(message_data))  # Send the message to the extracted server
                print("Message sent to", extracted_server)
        except Exception as e:
            print(f"Failed to connect to {extracted_server}: {e}")  # Handle connection errors

async def broadcast_client_update():
    update_message = json.dumps({
        "type": "client_update",
        "sender": "localhost:8765",
        "clients": list(connected_clients.keys())
    })
    for server_url in neighborhood_servers.values():
        async with websockets.connect(server_url) as server_ws:
            await server_ws.send(json.dumps(update_message))

async def send_initial_hello():
    # This server's hello message
    hello_message = {
        "data": {
            "type": "server_hello",
            "sender": "localhost:8765"
        }
    }
    for server_url in neighborhood_servers.values():
        async with websockets.connect(server_url) as server_ws:
            await server_ws.send(json.dumps(hello_message))

async def server_main():
    server = await websockets.serve(handler, "localhost", 8765)
    print("Server started on ws://localhost:8765")

    # At startup, perform initial hello to known servers, if any
    await send_initial_hello()

    await server.wait_closed()

asyncio.run(server_main())