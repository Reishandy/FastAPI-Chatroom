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
**GET /room**

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

```javascript
const socket = new WebSocket("ws://yourserver.com/ws/chat/room1?token=your_access_token");

socket.onopen = () => console.log("Connected");
socket.onmessage = (event) => console.log("New message:", JSON.parse(event.data));
socket.onclose = () => console.log("Disconnected");
```

#### **Sending Messages**
```json
{
    "type": "message",
    "content": "Hello, world!"
}
```

#### **Receiving Messages**
```json
{
    "type": "new_message",
    "message": {
        "message_id": 10,
        "user_id": "user123",
        "username": "JohnDoe",
        "content": "Hey there!",
        "timestamp": "2025-03-12T10:00:00Z"
    }
}
```

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

