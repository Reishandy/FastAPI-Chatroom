from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, HTTPException, Body, Header
from fastapi.params import Depends
from pydantic import BaseModel, Field
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

import app.handler as handler


# TODO: Create
#  - change password
#  - change username
#  ------------
#  - join room
#  - leave room
#  - kick user
#  - ban user
#  - unban user


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                          MODELS                          ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ BASE MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Response(BaseModel):
    message: str = Field(..., description="The response message", examples=["ok"])


class Tokens(BaseModel):
    type: str = Field(..., description="The token type", examples=["Bearer"])
    access_token: str = Field(..., description="The access token", examples=["<access_token>"])


class RefreshToken(Tokens):
    refresh_token: str = Field(..., description="The refresh token", examples=["<refresh_token>"])


class UserDetails(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["johndoe@example.com"])
    username: str = Field(..., description="The username of the user", examples=["johndoe"])


class Room(BaseModel):
    room_id: str = Field(..., description="The ID of the room", examples=["room1"])
    name: str = Field(..., description="The name of the room", examples=["Room1"])
    description: str = Field(..., description="The description of the room", examples=["Room1 description"])


class RoomWithoutID(BaseModel):
    name: str = Field(..., description="The name of the room", examples=["Room1"])
    description: str = Field(..., description="The description of the room", examples=["Room1 description"])


class RoomDetails(Room):
    owner: str = Field(..., description="The owner of the room", examples=["user_id1"])
    private: bool = Field(..., description="The privacy status of the room", examples=[True])
    users: list[str] = Field(..., description="The list of users in the room", examples=[["user_id1", "user_id2"]])
    created_at: str = Field(..., description="The creation date of the room",
                            examples=["1980-01-01T00:00:00.000000+00:00"])


class RoomDetailsWithoutUsers(Room):
    owner: str = Field(..., description="The owner of the room", examples=["user_id1"])
    private: bool = Field(..., description="The privacy status of the room", examples=[True])
    created_at: str = Field(..., description="The creation date of the room",
                            examples=["1980-01-01T00:00:00.000000+00:00"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ INPUT MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class User(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    password: str = Field(..., description="The password of the user", examples=["password123"])


class Register(User):
    username: str = Field(..., description="The username of the user", examples=["johndoe"])


class VerifyEmail(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    code: str = Field(..., description="The verification code", examples=["123456"])


class RoomCreate(Room):
    password: str | None = Field(None, description="The password of the room if any, this makes the room private",
                                 examples=["password123"])


class RoomUpdate(RoomWithoutID):
    password: str | None = Field(None, description="The password of the room if any, this makes the room private",
                                 examples=["password123"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ OUTPUT MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class UserResponse(Response):
    user_details: UserDetails = Field(..., description="The user details", examples=[{
        "email": "johndoe@example.com",
        "username": "johndoe"
    }])


class LoginResponse(Response):
    tokens: RefreshToken = Field(..., description="The access token and refresh token", examples=[{
        "access_token": "<access_token>",
        "refresh_token": "<refresh_token>",
        "type": "Bearer"
    }])
    user_id: str = Field(..., description="The ID of the logged in user", examples=["user_id1"])


class RefreshResponse(Response):
    tokens: Tokens = Field(..., description="The access token", examples=[{
        "access_token": "<access_token>",
        "type": "Bearer"
    }])


class RoomResponse(Response):
    room: RoomDetails = Field(..., description="The room details", examples=[{
        "room_id": "Room1",
        "name": "Room1",
        "description": "Room1 description",
        "owner": "user_id1",
        "private": True,
        "users": ["user_id1", "user_id2"],
        "created_at": "1980-01-01T00:00:00.000000+00:00"
    }])


class RoomListResponse(Response):
    rooms: list[RoomDetailsWithoutUsers] = Field(..., description="The list of rooms", examples=[{
        "room_id": "Room1",
        "name": "Room1",
        "description": "Room1 description",
        "owner": "johndoe@example.com",
        "private": True,
        "created_at": "1980-01-01T00:00:00.000000+00:00"
    }])


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                         FASTAPI                          ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the app
    handler.initialize()

    # Ensure indexes
    await handler.ensure_indexes(handler.DB)

    yield


app = FastAPI(lifespan=lifespan)


# Custom exception handler to change {detail} to {message} for more unified response
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )


# Authentication dependency to validate the access token
async def authenticate(Authorization: str = Header(description="Bearer access token")) -> str:
    """
    Validate the JWT access token from the Authorization header, and return the email of the user as an identifier.

    :param Authorization: The Authorization header
    :return: The email of the user
    """
    if not Authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token")

    if not Authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token")

    access_token: str = Authorization.split("Bearer ")[1]

    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token")

    try:
        return await handler.verify_access_token(access_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.get(
    "/",
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "description": "Health check",
            "content": {"application/json": {"example": {"message": "ok"}}}
        }})
async def root() -> dict[str, str]:
    """
    Health check endpoint
    """
    return {"message": "ok"}


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                 AUTHENTICATION ENDPOINTS                 ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@app.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=Response,
    responses={
        status.HTTP_201_CREATED: {
            "description": "User registered",
            "content": {"application/json": {"example": {"message": "ok"}}}
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad request",
            "content": {"application/json": {"example": {"message": "<error message>"}}},
        },
        status.HTTP_409_CONFLICT: {
            "description": "User already exists",
            "content": {"application/json": {"example": {"message": "User already exists"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def register(
        user: Annotated[Register, Body(
            title="User register details",
            description="Endpoint to register a new user."
        )]) -> Response:
    """
    Register a new user, put the user in email verification pending list.
    Access /verify to verify the email, then the user is moved to the users collection (active users).
    """
    try:
        await handler.add_user_to_verification_queue(**user.model_dump())
        return Response(message="ok")
    except ValueError as e:
        if str(e) == "User already exists":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/verify",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Email verified",
            "content": {"application/json": {"example": {"message": "ok"}}}
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad request",
            "content": {"application/json": {"example": {"message": "<error message>"}}},
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "User not found",
            "content": {"application/json": {"example": {"message": "Verification not found"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def verify_email(
        verify: Annotated[VerifyEmail, Body(
            title="Email verification details",
            description="Endpoint to verify the email of a user."
        )]) -> Response:
    """
    Verify the email of a user, move the user from email verification queue to active users.
    """
    try:
        await handler.verify_email(**verify.model_dump())
        return Response(message="ok")
    except ValueError as e:
        if str(e) == "Verification not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verification not found")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=LoginResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "User logged in",
            "content": {"application/json": {"example": {"message": "ok", "tokens": {
                "access_token": "<access_token>",
                "refresh_token": "<refresh_token>",
                "type": "Bearer"}}}},
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad request",
            "content": {"application/json": {"example": {"message": "<error message>"}}},
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "User not found",
            "content": {"application/json": {"example": {"message": "User not found"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def login(
        user: Annotated[User, Body(
            title="User login details",
            description="Endpoint to login a user."
        )]) -> LoginResponse:
    """
    Login a user, return the access token and refresh token and user_id.
    """

    try:
        login_result: tuple = await handler.login(**user.model_dump())
        tokens: dict[str, str] = login_result[0]
        user_id: str = login_result[1]["user_id"]
        return LoginResponse(message="ok", tokens=RefreshToken(**tokens), user_id=user_id)
    except ValueError as e:
        if str(e) == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.get(
    "/refresh",
    status_code=status.HTTP_200_OK,
    response_model=RefreshResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Token refreshed",
            "content": {"application/json": {"example": {"message": "ok", "tokens": {
                "access_token": "<access_token>", "type": "Bearer"}}}},
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def refresh_access_token(
        Authorization: Annotated[str, Header(description="Bearer refresh token")]
) -> RefreshResponse:
    """
    Refresh the access token using the refresh token.
    """
    try:
        if not Authorization.startswith("Bearer "):
            raise ValueError("Refresh token")

        refresh_token: str = Authorization.split("Bearer ")[1]

        new_access_token: str = await handler.issue_new_access_token(refresh_token)
        return RefreshResponse(message="ok", tokens=Tokens(access_token=new_access_token, type="Bearer"))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.get(
    "/user/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=UserResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "User details",
            "content": {"application/json": {
                "example": {"message": "ok", "email": "johndoe@exaample.com", "username": "johndoe"}}}
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "User not found",
            "content": {"application/json": {"example": {"message": "User not found"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def get_user(user_id: str, _: str = Depends(authenticate)) -> UserResponse:
    """
    Get the details of a user.
    """
    try:
        user: dict[str, str] = await handler.get_user(user_id)
        return UserResponse(message="ok", user_details=UserDetails(**user))
    except ValueError as e:
        if str(e) == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                    CHATROOM ENDPOINTS                    ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@app.get(
    "/room",
    status_code=status.HTTP_200_OK,
    response_model=RoomListResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Rooms list",
            "content": {"application/json": {"example": {"message": "ok", "rooms": [{
                "room_id": "Room1",
                "name": "Room1",
                "description": "Room1 description",
                "owner": "user_id1",
                "created_at": "1980-01-01T00:00:00.000000+00:00"
            }]}}},
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def get_rooms(_: str = Depends(authenticate)) -> RoomListResponse:
    """
    Get the list of public rooms.
    """
    try:
        rooms: list[dict[str, str]] = await handler.get_public_rooms()
        return RoomListResponse(message="ok", rooms=[RoomDetailsWithoutUsers(**room) for room in rooms])
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.get(
    "/room/{room_id}",
    status_code=status.HTTP_200_OK,
    response_model=RoomResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Room details",
            "content": {"application/json": {"example": {"message": "ok", "room": {
                "room_id": "Room1",
                "name": "Room1",
                "description": "Room1 description",
                "owner": "user_id1",
                "private": True,
                "users": ["user_id1", "user_id2"],
                "created_at": "1980-01-01T00:00:00.000000+00:00"
            }}}}
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Room not found",
            "content": {"application/json": {"example": {"message": "Room not found"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def get_room(room_id: str, _: str = Depends(authenticate)) -> RoomResponse:
    """
    Get the details of a room.
    """
    try:
        room: dict[str, str] = await handler.get_room(room_id)
        return RoomResponse(message="ok", room=RoomDetails(**room))
    except ValueError as e:
        if str(e) == "Room not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/room",
    status_code=status.HTTP_201_CREATED,
    response_model=Response,
    responses={
        status.HTTP_201_CREATED: {
            "description": "Room created",
            "content": {"application/json": {"example": {"message": "ok"}}}
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad request",
            "content": {"application/json": {"example": {"message": "<error message>"}}},
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_409_CONFLICT: {
            "description": "Room already exists",
            "content": {"application/json": {"example": {"message": "Room ID taken"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def create_room(
        room: Annotated[RoomCreate, Body(
            title="Room details",
            description="Endpoint to create a new room."
        )],
        user_id: str = Depends(authenticate)) -> Response:
    """
    Create a new room, with the user as the owner.
    If password is provided, the room is set to private.
    """
    try:
        await handler.create_room(owner=user_id, **room.model_dump())
        return Response(message="ok")
    except ValueError as e:
        if str(e) == "Room ID taken":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Room ID taken")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.put(
    "/room/{room_id}",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Room updated",
            "content": {"application/json": {"example": {"message": "ok"}}}
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad request",
            "content": {"application/json": {"example": {"message": "<error message>"}}},
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Room not found",
            "content": {"application/json": {"example": {"message": "Room not found"}}}
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {"application/json": {"example": {"message": "Forbidden"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def update_room(
        room_id: str,
        room: Annotated[RoomUpdate, Body(
            title="Room details",
            description="Endpoint to update a room."
        )],
        user_id: str = Depends(authenticate)) -> Response:
    """
    Update the details of a room.
    """
    try:
        await handler.update_room(user_id=user_id, room_id=room_id, **room.model_dump())
        return Response(message="ok")
    except ValueError as e:
        if str(e) == "Room not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

        if str(e) == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.delete(
    "/room/{room_id}",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Room deleted",
            "content": {"application/json": {"example": {"message": "ok"}}}
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad request",
            "content": {"application/json": {"example": {"message": "<error message>"}}},
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Unauthorized",
            "content": {"application/json": {"example": {"message": "Unauthorized"}}}
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Room not found",
            "content": {"application/json": {"example": {"message": "Room not found"}}}
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {"application/json": {"example": {"message": "Forbidden"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def delete_room(
        room_id: str,
        user_id: str = Depends(authenticate)) -> Response:
    """
    Delete a room.
    """
    try:
        await handler.delete_room(room_id=room_id, user_id=user_id)
        return Response(message="ok")
    except ValueError as e:
        if str(e) == "Room not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")

        if str(e) == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")
