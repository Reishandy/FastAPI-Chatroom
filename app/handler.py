from os import getenv
from re import match
from secrets import choice
from datetime import datetime, timedelta

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorClient
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from pymongo.errors import OperationFailure

from app.email import send_verification_email

#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                     GLOBAL VARIABLES                     ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

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
    global DB, REFRESH_TOKEN_EXPIRATION_DAYS, ACCESS_TOKEN_EXPIRATION_DAYS, VERIFICATION_CODE_EXPIRATION_MINUTES

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
    if "email_1" not in existing_indexes:
        await db.users.create_index("email", unique=True)

    # Check and create index for verification_queue collection
    existing_indexes = await db.verification_queue.index_information()
    if "email_1" not in existing_indexes:
        await db.verification_queue.create_index("email", unique=True)


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
        await DB.verification_queue.replace_one(
            {"email": email},
            {
                "email": email,
                "hashed_password": hash_password(password),
                "username": username,
                "verification_code": verification_code,
                "timestamp": datetime.now()
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
        stored_verification_code = user["verification_code"]
        timestamp = user["timestamp"]

        if code != stored_verification_code:
            raise ValueError("Invalid verification code")
        if timestamp < datetime.now() - timedelta(minutes=VERIFICATION_CODE_EXPIRATION_MINUTES):
            raise ValueError("Verification code expired")

        # Move the user to the users collection
        await DB.users.insert_one({
            "email": user["email"],
            "hashed_password": user["hashed_password"],
            "username": user["username"],
            "created_at": datetime.now()
        })

        # Remove the user from the verification queue
        await DB.verification_queue.delete_one({"email": email})
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
