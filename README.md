# Rei's Chatroom

Rei's Chatroom is a real-time, WebSocket-based chat application built using FastAPI and MongoDB.

## Features

- **Real-Time Communication:** Messages are instantly delivered via WebSockets.
- **Multi-Room Support:** Users can create and join different chat rooms.
- **User Authentication:** Secure login and email verification.
- **Message History:** Stores chat messages per room.
- **REST & WebSocket API:** Provides real-time updates and standard API endpoints.

## API Endpoints

### **Authentication**

#### **Register a User**
**POST /register**
```json
{
    "email": "user@example.com",
    "password": "securepassword",
    "username": "JohnDoe"
}
```

#### **Verify Email**
**POST /verify**
```json
{
    "email": "user@example.com",
    "code": "123456"
}
```

#### **Login**
**POST /login**
```json
{
    "email": "user@example.com",
    "password": "securepassword"
}
```

#### **Refresh Token**
**GET /refresh**
(Requires `Authorization: Bearer <refresh_token>` header)

### **User Management**

#### **Get User Info**
**GET /user**

#### **Change Username**
**PUT /user/username**
```json
{
    "username": "NewUsername"
}
```

#### **Change Password**
**PUT /user/password**
```json
{
    "password": "oldpassword",
    "new_password": "newsecurepassword"
}
```

### **Room Management**

#### **List Public Rooms**
**GET /public**

#### **List User Joined Rooms**
**GET /joined**

#### **Get Room Details**
**GET /room/{room_id}**

#### **Create a Room**
**POST /room**
```json
{
    "name": "RoomName",
    "description": "Room Description",
    "password": "optionalpassword"
}
```

#### **Update a Room**
**PUT /room/{room_id}**
```json
{
    "name": "UpdatedRoomName",
    "description": "Updated Description",
    "password": "newpassword"
}
```

#### **Delete a Room**
**DELETE /room/{room_id}**

### **Joining & Leaving Rooms**

#### **Join a Room**
**POST /room/{room_id}/join**
```json
{
    "password": "optionalpassword"
}
```

#### **Leave a Room**
**POST /room/{room_id}/leave**

### **WebSocket Endpoints**

#### **Connect to WebSocket**
```
wss://yourserver.com/ws/chat/{room_id}?token={access_token}
```

Example JavaScript WebSocket client:

```javascript
const socket = new WebSocket("ws://yourserver.com/ws/chat/room1?token=your_access_token");

socket.onopen = () => console.log("Connected");
socket.onmessage = (event) => console.log("New message:", JSON.parse(event.data));
socket.onclose = () => console.log("Disconnected");
```

#### **Initial State**
The server sends the initial state of the room, including the last read message ID and a range of messages.

```json
{
    "type": "initial_state",
    "last_read_id": 1,
    "messages": [
        {
            "message_id": 1,
            "user_id": "user_id",
            "username": "username",
            "email": "email",
            "content": "content",
            "timestamp": "timestamp"
        }
    ]
}
```

#### **Fetch Messages**
The client requests a range of messages from the room, for client-side pagination.

```json
{
    "type": "fetch",
    "from_id": 1,
    "to_id": 10
}
```

The server responds with the requested messages.

```json
{
    "type": "fetch_response",
    "messages": [
        {
            "message_id": 1,
            "user_id": "user_id",
            "username": "username",
            "email": "email",
            "content": "content",
            "timestamp": "timestamp"
        }
    ]
}
```

#### **Set Latest Read Message ID**
The client sends the latest read message ID to the server.

```json
{
    "type": "set_last_read",
    "message_id": 10
}
```

#### **Listen for Latest Messages**
The client request to starts listening for the latest messages.

```json
{
    "type": "listen_latest"
}
```

The server will start sending latest messages to the client.

```json
{
    "type": "latest_message",
    "message": {
        "message_id": 1,
        "user_id": "user_id",
        "username": "username",
        "email": "email",
        "content": "content",
        "timestamp": "timestamp"
    }
}
```

#### **Send a Message**
The client sends a new message to the server.

```json
{
    "type": "message",
    "content": "Hello, World!"
}
```

### WebSocket Chatroom Recommended Flow
1. Server sends initial state:  
   - The server sends the initial state of the room, including the last read message ID and a range of messages (-30 to +50).

2. Client checks initial state:  
   - The client checks if the initial state max message ID is >= 50. If not, the user starts listening for the latest messages.

3. Client sends fetch request:  
   - The client sends a fetch request based on the last read ID and their own pagination mechanism. If the response is empty or less than the fetch to_id, the client starts listening for the latest messages.

4. Client sets last read message ID:  
   - The client sends a set_last_read request to update the last read message ID after receiving the fetch response (get max message ID).

5. Client sends a message:  
   - The client can send a message to the room at any time.
   - The server will automatically update the latest message ID for the user.

6. Client listens for latest messages:
   - The client listens for the latest messages if the initial state max message ID is < 50 and the fetch response is empty or less than the fetch to_id.

> **Note:** Make sure to properly close the WebSocket connection and handle websocket errors.

### **Websocket Errors**
1. **4001: Invalid Token or 4001: Unauthorized**
   - The access token is invalid or expired.

2. **1008: ValueError**
   - If the room ID not found or invalid.
   - If the user is forbidden to access the room, not joined.

3. **1011: Internal Server Error**
   - If there is an internal server error.

## Installation

### Prerequisites
- **Python 3.8+**
- **MongoDB** instance running
- **FastAPI** and **Uvicorn**

### Setup Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/Reishandy/Reis-Chatroom.git
   cd reis-chatroom
   ```

2. **Create a Virtual Environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate  # Windows
   ```

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Setup Environment Variables:**

   Create a `.env` file in the project root with the following content:
   
   ```env
   SECRET_KEY=your_secret_key 256-bit
   MONGODB_USERNAME=your_mongodb_username
   MONGODB_PASSWORD=your_mongodb_password
   MONGODB_DATABASE=your_mongodb_database
   MONGODB_HOST=your_mongodb_server_host
   MONGODB_PORT=yout_mongodb_server_port
   MONGODB_URI=yout_mongodb_uri
   REFRESH_TOKEN_EXPIRATION_DAYS=7
   ACCESS_TOKEN_EXPIRATION_MINUTES=15
   VERIFICATION_CODE_EXPIRATION_MINUTES=10
   ```
> **Note:** You can either fill the mongodb uri or the individual fields, or both as long as at least one of them is filled.


5. **Run the Application:**

   ```bash
   uvicorn app.main:app --reload
   ```

### Optional: Docker Installation

You can also deploy this project using Docker for easier setup.

1. **Change CMD in Dockerfile:**

   Modify the --host and --port arguments in the `CMD` instruction of the `Dockerfile` to match your deployment configuration.

   ```Dockerfile
   CMD ["uvicorn", "app.main:app", "--host", "<server ip>", "--port", "<server port>"]
   ```

1. **Build the Docker image:**
   ```bash
   docker build -t chatroom-api .
   ```

2. **Run the Docker container:**
   ```bash
   docker run -d --name chatroom-api-container --network host --restart always chatroom-api
   ```

> **Note:** Ensure that your `.env` file is correctly configured and available in the same directory. (See [Setup Steps](#setup-steps))

## Contributing

Contributions are welcome! If you have ideas for new features or improvements.

## 📄 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits

Created by [Reishandy](https://github.com/Reishandy)

