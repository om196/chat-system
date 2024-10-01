# Secure Chat Application

## Overview
This is a secure chat application based on the OLAF/Neighbourhood protocol. It supports real-time messaging with encryption, user authentication using RSA keys. The system is designed to operate without a central server, leveraging WebSocket technology for peer-to-peer communication.

## Features
- **User Authentication**: Each user connects to the server using unique RSA key pairs.
- **Encrypted Messaging**: Chat messages are encrypted using AES, ensuring secure communication.
- **Client List Requests**: Users can request a list of currently connected clients.

## Technologies Used
- Python 3.x
- WebSockets (for real-time communication)
- Cryptography library (for encryption and signing)
- HTTP Server (for file uploads)

## Installation

1. **Clone the Repository**
    ```bash
    git clone https://github.com/om196/chat-system.git
    cd chat-system
    ```

2. **Setup Python Environment**
    - Ensure Python 3.6 or later is installed.
    - Create and activate a virtual environment:
        ```bash
        python -m venv venv
        source venv/bin/activate  # On Windows use: venv\Scripts\activate
        ```

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Starting the Server

1. Open a terminal and navigate to the `src` directory.
2. Run the server:
    ```bash
    python server.py
    ```

### Starting the Client

1. In another terminal, navigate to the `src` directory.
2. Run the client:
    ```bash
    python client.py
    ```

### Interacting with the Application

- Upon starting the client, it will prompt you to enter selection options.
- To send a private message, select the recipient from list.
- To send a public message, select type 2.
- To get list of connected clients, select type 3.