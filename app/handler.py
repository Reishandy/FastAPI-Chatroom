from os import getenv
from re import match
from secrets import choice, token_urlsafe
from datetime import datetime, timedelta, UTC
from typing import Any, Coroutine
from uuid import uuid4

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorClient
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from pymongo.errors import OperationFailure
from jwt import encode, decode, ExpiredSignatureError, InvalidTokenError

from app.email import send_verification_email

#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                     GLOBAL VARIABLES                     ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

SECRET_KEY: str
DB: AsyncIOMotorDatabase
REFRESH_TOKEN_EXPIRATION_DAYS: int = 30
ACCESS_TOKEN_EXPIRATION_DAYS: int = 1
VERIFICATION_CODE_EXPIRATION_MINUTES: int = 10
PH: PasswordHasher = PasswordHasher()

# Load environment variables
load_dotenv()


def initialize() -> None:
    """
    Initialize the global variables
    """
    global SECRET_KEY, DB, REFRESH_TOKEN_EXPIRATION_DAYS, ACCESS_TOKEN_EXPIRATION_DAYS, VERIFICATION_CODE_EXPIRATION_MINUTES

    # Set the secret key
    SECRET_KEY = getenv("SECRET_KEY")
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY is not set")

    # Set the expiration times if they are set in the environment variables
    REFRESH_TOKEN_EXPIRATION_DAYS = int(getenv("REFRESH_TOKEN_EXPIRATION_DAYS", REFRESH_TOKEN_EXPIRATION_DAYS))
    ACCESS_TOKEN_EXPIRATION_DAYS = int(getenv("ACCESS_TOKEN_EXPIRATION_DAYS", ACCESS_TOKEN_EXPIRATION_DAYS))
    VERIFICATION_CODE_EXPIRATION_MINUTES = int(
        getenv("VERIFICATION_CODE_EXPIRATION_MINUTES", VERIFICATION_CODE_EXPIRATION_MINUTES))

    # Set the database connection
    mongo_uri: str = getenv("MONGODB_URI")
    mongo_username: str = getenv("MONGODB_USERNAME")
    mongo_password: str = getenv("MONGODB_PASSWORD")
    mongo_database: str = getenv("MONGODB_DATABASE")
    mongo_host: str = getenv("MONGODB_HOST")
    mongo_port: str = getenv("MONGODB_PORT")

    if not mongo_uri:
        mongo_uri = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/{mongo_database}"

    # Connect and return the database
    client = AsyncIOMotorClient(mongo_uri)
    # Get the database from the URI if MONGO_DATABASE is not set
    DB = client[mongo_database if mongo_database else mongo_uri.split("/")[-1]]


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    """
    Ensure that the necessary indexes are created in the database collections.

    :param db: The database instance.
    """
    # Check and create index for users collection
    existing_indexes = await db.users.index_information()
    if "user_id_1" not in existing_indexes:
        await db.users.create_index("user_id", unique=True)
    if "refresh_token.token_1" not in existing_indexes:
        await db.users.create_index("refresh_token.token", unique=True)

    # Check and create index for verification_queue collection
    existing_indexes = await db.verification_queue.index_information()
    if "email_1" not in existing_indexes:
        await db.verification_queue.create_index("email_1", unique=True)

    # Check and create index for room collection
    existing_indexes = await db.room.index_information()
    if "room_id_1" not in existing_indexes:
        await db.room.create_index("room_id", unique=True)
    if "owner_1" not in existing_indexes:
        await db.chatrooms.create_index("owner")  # Non-unique index for queries
    if "users_1" not in existing_indexes:
        await db.chatrooms.create_index("users")  # Non-unique index for queries


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                         HANDLERS                         ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ AUTH HANDLERS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
async def add_user_to_verification_queue(email: str, password: str, username: str) -> None:
    """
    Add the user into a email verification queue and sends a verification code to the user's email,
    waiting for verification.

    :param email: The email of the user.
    :param password: The password of the user.
    :param username: The username of the user.
    """
    if not validate_email(email):
        raise ValueError("Invalid email")

    verification_code: str = create_verification_code()

    try:
        # Check if the email is already in the users collection / registered
        user = await DB.users.find_one({"email": email})
        if user:
            raise ValueError("User already exists")

        await DB.verification_queue.replace_one(
            {"email": email},
            {
                "email": email,
                "hashed_password": hash_password(password),
                "username": username,
                "verification_code": verification_code,
                "timestamp": datetime.now(UTC)
            },
            upsert=True
        )

    except OperationFailure as e:
        raise RuntimeError(str(e))

    # Send the verification email
    # INFO: You need to re-implement this function to send the email using your own service
    send_verification_email(email, verification_code, VERIFICATION_CODE_EXPIRATION_MINUTES)


async def verify_email(email: str, code: str) -> None:
    """
    Verify the email of the user using the verification code, then move the user to the users collection.

    :param email: The email of the user.
    :param code: The verification code to verify.
    """
    if not validate_email(email):
        raise ValueError("Invalid email")

    try:
        # Get the user from the verification queue
        user = await DB.verification_queue.find_one({"email": email})
        if not user:
            raise ValueError("Verification not found")

        # Perform verification
        # Ensure timestamp has timezone info
        stored_verification_code = user["verification_code"]
        timestamp = user["timestamp"]
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)

        if code != stored_verification_code:
            raise ValueError("Invalid verification code")
        if timestamp < datetime.now(UTC) - timedelta(minutes=VERIFICATION_CODE_EXPIRATION_MINUTES):
            raise ValueError("Verification code expired")

        # Move the user to the users collection
        await DB.users.insert_one({
            "user_id": create_user_id(),
            "email": user["email"],
            "hashed_password": user["hashed_password"],
            "username": user["username"],
            "created_at": datetime.now(UTC)
        })

        # Remove the user from the verification queue
        await DB.verification_queue.delete_one({"email": email})
    except OperationFailure as e:
        raise RuntimeError(str(e))


async def login(email: str, password: str) -> tuple[dict[str, str], dict[str, str]]:
    """
    Login the user and return the access token and refresh token, and user_id.

    :param email: The email of the user.
    :param password: The password of the user.
    :return: The refresh token and access token as a dictionary.
    """
    if not validate_email(email):
        raise ValueError("Invalid email")

    try:
        # Get the user from the users collection
        user = await DB.users.find_one({"email": email})
        if not user:
            raise ValueError("User not found")

        # Verify the password
        if not verify_password(password, user["hashed_password"]):
            raise ValueError("Invalid password")

        # Create and append the refresh token to the user
        refresh_token = create_refresh_token()
        await DB.users.update_one(
            {"email": email},
            {"$set": {"refresh_token": {
                "token": refresh_token,
                "issued_at": datetime.now(UTC),
                "expiration": datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRATION_DAYS)
            }}},
            upsert=True
        )

        # Create the first access token
        user_id: str = user["user_id"]
        access_token = create_access_token(user_id)

        return {"refresh_token": refresh_token, "access_token": access_token, "type": "Bearer"}, {"user_id": user_id}
    except OperationFailure as e:
        raise RuntimeError(str(e))


async def issue_new_access_token(refresh_token: str) -> str:
    """
    Issue a new access token using the refresh token.

    :param refresh_token: The refresh token to use.
    :return: The new access token.
    """
    try:
        # Get the user from the users collection
        user = await DB.users.find_one({"refresh_token.token": refresh_token})
        if not user:
            raise ValueError("Refresh token not found")

        # Ensure expiration time has timezone info
        expiration = user["refresh_token"]["expiration"]
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)

        # Check if the refresh token is expired
        if expiration < datetime.now(UTC):
            raise ValueError("Refresh token expired")

        # Create new access token
        return create_access_token(user["user_id"])
    except OperationFailure as e:
        raise RuntimeError(str(e))


async def verify_access_token(token: str) -> str:
    """
    Verify the access token and return the user ID

    :param token: The access token to verify.
    :return: The user ID.
    """
    try:
        decoded = decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["sub"]
    except ExpiredSignatureError:
        raise ValueError("Token expired")
    except InvalidTokenError:
        raise ValueError("Invalid token")
    except Exception as e:
        raise RuntimeError(str(e))


async def get_user(user_id: str) -> dict:
    """
    Get the user from the users' collection.

    :param: The user ID of the user.
    :return: The user's email and username.
    """
    try:
        user = await DB.users.find_one({"user_id": user_id}, {"email": 1, "username": 1})
        if not user:
            raise ValueError("User not found")
        return user
    except OperationFailure as e:
        raise RuntimeError(str(e))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ CHATROOM HANDLERS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def create_room(room_id: str, name: str, description: str, owner: str, password: str | None = None) -> None:
    """
    Create a room with the given name and description.

    :param room_id: Unique identifier of the room.
    :param name: The name of the room.
    :param description: The description of the room.
    :param password: The password of the room.
    :param owner: The user_id of the owner of the room.
    """
    try:
        # Check if the room already exists
        room = await DB.room.find_one({"room_id": room_id})
        if room:
            raise ValueError("Room ID taken")

        await DB.room.insert_one({
            "room_id": room_id,
            "name": name,
            "description": description,
            "password": hash_password(password) if password else None,
            "private": True if password else False,
            "owner": owner,
            "created_at": datetime.now(UTC),
            "users": [owner]
        })
    except OperationFailure as e:
        raise RuntimeError(str(e))


async def get_room(room_id: str) -> dict[str, str]:
    """
    Get the room from the room collection.

    :param: The room ID of the room.
    :return: The room's name, description, owner, and users.
    """
    try:
        room = await DB.room.find_one({"room_id": room_id}, {"password": 0, "_id": 0})
        if not room:
            raise ValueError("Room not found")
        return room
    except OperationFailure as e:
        raise RuntimeError(str(e))


async def get_public_rooms() -> list[dict[str, str]]:
    """
    Get all public rooms from the room collection.

    :return: A list of public rooms with their name, description, and owner.
    """
    try:
        rooms = await DB.room.find({"private": False}, {"password": 0, "_id": 0, "users": 0}).to_list(None)
        return rooms
    except OperationFailure as e:
        raise RuntimeError(str(e))


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                         HELPERS                          ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

def validate_email(email: str) -> bool:
    """
    Check if the email is valid using a regular expression.

    :param email: The email to check.
    :return: True if the email is valid, False otherwise.
    """
    if bool(match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email)):
        return True
    return False


def create_user_id() -> str:
    """
    Generate a random user ID with UUID4.

    :return: A random user ID as a string.
    """
    return str(uuid4())


def create_verification_code(length: int = 6) -> str:
    """
    Generate a random numerical verification code.

    :param length: The length of the verification code, default is 6.
    :return: A random numerical verification code as a string.
    """
    return ''.join(choice("0123456789") for _ in range(length))


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.

    :param password: The password to hash.
    :return: The hashed password.
    """
    return PH.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hashed password using Argon2id.

    :param password: The password to verify.
    :param hashed_password: The hashed password to verify against.
    :return: True if the password matches the hashed password, False otherwise.
    """
    try:
        return PH.verify(hashed_password, password)
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        return False


def create_refresh_token() -> str:
    """
    Create a secure refresh token using secrets' token_urlsafe function.

    :return: The refresh token as a string.
    """
    return token_urlsafe(128)


def create_access_token(user_id: str) -> str:
    """
    Create a JWT access token using the user_id as the subject.

    :param user_id: The user ID to use as the subject.
    :return: The access token as a string.
    """
    return encode(
        {"sub": user_id, "exp": datetime.now(UTC) + timedelta(days=ACCESS_TOKEN_EXPIRATION_DAYS),
         "iat": datetime.now(UTC)}, SECRET_KEY, algorithm="HS256"
    )