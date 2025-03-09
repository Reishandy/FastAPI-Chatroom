from os import getenv

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorClient

#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                     GLOBAL VARIABLES                     ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

DB: AsyncIOMotorDatabase
REFRESH_TOKEN_EXPIRATION_DAYS: int = 30
ACCESS_TOKEN_EXPIRATION_DAYS: int = 1
VERIFICATION_CODE_EXPIRATION_MINUTES: int = 10

# Load environment variables
load_dotenv()


def init() -> None:
    """
    Initialize the global variables
    """
    global DB, REFRESH_TOKEN_EXPIRATION_DAYS, ACCESS_TOKEN_EXPIRATION_DAYS, VERIFICATION_CODE_EXPIRATION_MINUTES

    # Set the expiration times if they are set in the environment variables
    REFRESH_TOKEN_EXPIRATION_DAYS = int(getenv("REFRESH_TOKEN_EXPIRATION_DAYS", REFRESH_TOKEN_EXPIRATION_DAYS))
    ACCESS_TOKEN_EXPIRATION_DAYS = int(getenv("ACCESS_TOKEN_EXPIRATION_DAYS", ACCESS_TOKEN_EXPIRATION_DAYS))
    VERIFICATION_CODE_EXPIRATION_MINUTES = int(
        getenv("VERIFICATION_CODE_EXPIRATION_MINUTES", VERIFICATION_CODE_EXPIRATION_MINUTES))

    print(REFRESH_TOKEN_EXPIRATION_DAYS, ACCESS_TOKEN_EXPIRATION_DAYS, VERIFICATION_CODE_EXPIRATION_MINUTES)

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
