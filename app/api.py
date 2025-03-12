from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, HTTPException, Body, Header
from fastapi.params import Depends
from pydantic import BaseModel, Field
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.websockets import WebSocket, WebSocketDisconnect

import handler


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
    name: str = Field(..., description="The name of the room", examples=["Room1"])
    description: str = Field(..., description="The description of the room", examples=["Room1 description"])


class RoomWithID(Room):
    room_id: str = Field(..., description="The ID of the room", examples=["room1"])


class RoomDetails(Room):
    owner: str = Field(..., description="The owner of the room", examples=["user_id1"])
    private: bool = Field(..., description="The privacy status of the room", examples=[True])
    users: list[str] = Field(..., description="The list of users in the room", examples=[["user_id1", "user_id2"]])
    created_at: str = Field(..., description="The creation date of the room",
                            examples=["1980-01-01T00:00:00.000000+00:00"])


class RoomDetailsWithID(RoomDetails):
    room_id: str = Field(..., description="The ID of the room", examples=["room1"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ INPUT MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class User(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    password: str = Field(..., description="The password of the user", examples=["password123"])


class Register(User):
    username: str = Field(..., description="The username of the user", examples=["johndoe"])


class VerifyEmail(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    code: str = Field(..., description="The verification code", examples=["123456"])


class RoomPassword(RoomWithID):
    password: str | None = Field(None, description="The password of the room if any",
                                 examples=["password123"])


class ChangeUsername(BaseModel):
    username: str = Field(..., description="The new username of the user", examples=["johndoe"])


class ChangePassword(BaseModel):
    password: str = Field(..., description="The new password of the user", examples=["password123"])
    new_password: str = Field(..., description="The new password of the user", examples=["password123"])


class JoinRoom(BaseModel):
    password: str | None = Field(None, description="The password of the room if any",
                                 examples=["password123"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ OUTPUT MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class UserResponse(Response):
    user_details: UserDetails = Field(..., description="The user details", examples=[{
        "email": "johndoe@example.com",
        "username": "johndoe"
    }])


class UserResponseWithJoinedRooms(UserResponse):
    rooms: list[Room] = Field(..., description="The list of rooms the user has joined", examples=[{
        "room_id": "Room1",
        "name": "Room1",
        "description": "Room1 description",
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
    rooms: list[RoomWithID] = Field(..., description="The list of rooms", examples=[{
        "room_id": "Room1",
        "name": "Room1",
        "description": "Room1 description",
    }])


class JoinedRoomResponse(Response):
    rooms: list[RoomDetailsWithID] = Field(..., description="The list of joined rooms", examples=[{
        "room_id": "Room1",
        "name": "Room1",
        "description": "Room1 description",
        "owner": "user_id1",
        "private": True,
        "users": ["user_id1", "user_id2"],
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


app = FastAPI(
    lifespan=lifespan,
    title="Rei's Chatroom API",
    description="API for Rei's Chatroom",
    version="1.3.0",
    openapi_components={
        "securitySchemes": {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }
    },
    openapi_security=[{"BearerAuth": []}]
)


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
        e_string: str = str(e)

        if e_string == "User already exists":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
        e_string: str = str(e)

        if e_string == "Verification not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
                "type": "Bearer"}, "user_id": "user_id1"}}},
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
        e_string: str = str(e)

        if e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.get(
    "/user",
    status_code=status.HTTP_200_OK,
    response_model=UserResponseWithJoinedRooms,
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
async def get_user(user_id: str = Depends(authenticate)) -> UserResponse:
    """
    Get the details of current user.
    """
    try:
        user: dict[str, str] = await handler.get_user_details(user_id)
        return UserResponseWithJoinedRooms(message="ok", user_details=UserDetails(**user),
                                           rooms=[])  # TODO: Get joined rooms
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
        user: dict[str, str] = await handler.get_user_details(user_id)
        return UserResponse(message="ok", user_details=UserDetails(**user))
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.put(
    "/user/username",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Username changed",
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
            "description": "User not found",
            "content": {"application/json": {"example": {"message": "User not found"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }})
async def change_username(
        username: Annotated[ChangeUsername, Body(
            title="Username change details",
            description="Endpoint to change the username of a user."
        )],
        user_id: str = Depends(authenticate)) -> Response:
    """
    Change the username of the user based on the JWT access token.
    """
    try:
        await handler.change_username(user_id=user_id, **username.model_dump())
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.put(
    "/user/password",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Password changed",
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
            "description": "User not found",
            "content": {"application/json": {"example": {"message": "User not found"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }})
async def change_password(
        password: Annotated[ChangePassword, Body(
            title="Password change details",
            description="Endpoint to change the password of a user."
        )],
        user_id: str = Depends(authenticate)) -> Response:
    """
    Change the password of the user based on the JWT access token.
    """
    try:
        await handler.change_password(user_id=user_id, **password.model_dump())
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                    CHATROOM ENDPOINTS                    ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@app.get(
    "/public",
    status_code=status.HTTP_200_OK,
    response_model=RoomListResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Rooms list",
            "content": {"application/json": {"example": {"message": "ok", "rooms": [{
                "room_id": "Room1",
                "name": "Room1",
                "description": "Room1 description",
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
        return RoomListResponse(message="ok", rooms=[RoomWithID(**room) for room in rooms])
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.get(
    "/joined",
    status_code=status.HTTP_200_OK,
    response_model=RoomListResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Rooms joined",
            "content": {"application/json": {"example": {"message": "ok", "rooms": [{
                "room_id": "Room1",
                "name": "Room1",
                "description": "Room1 description",
                "owner": "user_id1",
                "private": True,
                "users": ["user_id1", "user_id2"],
                "created_at": "1980-01-01T00:00:00.000000+00:00"
            }]}}}
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
async def get_joined_room(user_id: str = Depends(authenticate)) -> JoinedRoomResponse:
    """
    Returns user's joined room details.
    """
    try:
        rooms: list[dict[str, str]] = await handler.get_user_rooms(user_id)
        print(rooms)
        rooms1 = [RoomDetailsWithID(**room) for room in rooms]
        print(rooms1)
        rooms3 = JoinedRoomResponse(message="ok", rooms=rooms1)
        print(rooms3)
        return JoinedRoomResponse(message="ok", rooms=[RoomDetailsWithID(**room) for room in rooms])
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
        room: dict[str, str] = await handler.get_room_details(room_id)
        return RoomResponse(message="ok", room=RoomDetails(**room))
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
        room: Annotated[RoomPassword, Body(
            title="Room details",
            description="Endpoint to create a new room."
        )],
        user_id: str = Depends(authenticate)) -> Response:
    """
    Create a new room, with the user as the owner.
    If password is provided, the room is set to private.
    """
    print(room.model_dump())

    try:
        await handler.create_room(owner=user_id, **room.model_dump())
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room ID taken":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
        room: Annotated[RoomPassword, Body(
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
        e_string: str = str(e)

        if e_string == "Room not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
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
        e_string: str = str(e)

        if e_string == "Room not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/room/{room_id}/join",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Room joined",
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
        status.HTTP_409_CONFLICT: {
            "description": "Already joined",
            "content": {"application/json": {"example": {"message": "Already joined"}}}
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
async def join_room(
        room_id: str,
        password: Annotated[JoinRoom, Body(
            title="Room password",
            description="Password to join a private room."
        )],
        user_id: str = Depends(authenticate)) -> Response:
    """
    Join a room. status 403 forbidden if the user is banned.
    """
    try:
        await handler.join_room(room_id=room_id, user_id=user_id, **password.model_dump())
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room not found" or e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "Already joined":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e_string)

        if e_string == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/room/{room_id}/leave",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "Room left",
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
        status.HTTP_409_CONFLICT: {
            "description": "User not in room",
            "content": {"application/json": {"example": {"message": "User not in room"}}}
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"message": "Internal server error: {error}"}}}
        }
    })
async def leave_room(
        room_id: str,
        user_id: str = Depends(authenticate)) -> Response:
    """
    Leave a room.
    """
    try:
        await handler.leave_room(room_id=room_id, user_id=user_id)
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room not found" or e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "User not in room":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/room/{room_id}/kick/{target_id}",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "User kicked",
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
        status.HTTP_409_CONFLICT: {
            "description": "User not in room",
            "content": {"application/json": {"example": {"message": "User not in room"}}}
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
async def kick_user(
        room_id: str,
        target_id: str,
        user_id: str = Depends(authenticate)) -> Response:
    """
    Kick a user from a room.
    """
    try:
        await handler.kick_user(room_id=room_id, owner_id=user_id, target_id=target_id)
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room not found" or e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "User not in room":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e_string)

        if e_string == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/room/{room_id}/ban/{target_id}",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "User banned",
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
        status.HTTP_409_CONFLICT: {
            "description": "User not in room",
            "content": {"application/json": {"example": {"message": "User not in room"}}}
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
async def ban_user(
        room_id: str,
        target_id: str,
        user_id: str = Depends(authenticate)) -> Response:
    """
    Ban a user from a room, also kicks the user.
    """
    try:
        await handler.ban_user(room_id=room_id, owner_id=user_id, target_id=target_id)
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room not found" or e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "User not in room":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e_string)

        if e_string == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.post(
    "/room/{room_id}/unban/{target_id}",
    status_code=status.HTTP_200_OK,
    response_model=Response,
    responses={
        status.HTTP_200_OK: {
            "description": "User unbanned",
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
async def unban_user(
        room_id: str,
        target_id: str,
        user_id: str = Depends(authenticate)) -> Response:
    """
    Unban a user from a room, does not automatically join the user.
    """
    try:
        await handler.unban_user(room_id=room_id, owner_id=user_id, target_id=target_id)
        return Response(message="ok")
    except ValueError as e:
        e_string: str = str(e)

        if e_string == "Room not found" or e_string == "User not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e_string)

        if e_string == "Forbidden":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=e_string)

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e_string)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")


@app.websocket("/room/{room_id}")
async def chatroom(
        websocket: WebSocket,
        room_id: str) -> None:
    """
    Websocket connection to send and receive messages from a room.
    """
    await websocket.accept()

    # Get authorization header
    headers = dict(websocket.headers)
    authorization = headers.get("authorization")

    if not authorization:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    try:
        # Verify token and get user_id
        user_id = await authenticate(authorization)

        await handler.chatroom(websocket=websocket, room_id=room_id, user_id=user_id)
    except HTTPException:
        await websocket.close(code=4001, reason="Invalid token")
    except WebSocketDisconnect:
        pass
    except ValueError as e:
        await websocket.close(code=1008, reason=str(e))
    except Exception as e:
        await websocket.close(code=1011, reason=f"Internal server error: {str(e)}")
