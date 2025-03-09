from contextlib import asynccontextmanager
from typing import Annotated, Any, Coroutine

from fastapi import FastAPI, HTTPException, Body, Header
from fastapi.params import Depends
from pydantic import BaseModel, Field, ValidationError
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

import app.handler as handler


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                          MODELS                          ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ INPUT MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class User(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    password: str = Field(..., description="The password of the user", examples=["password123"])


class Register(User):
    username: str = Field(..., description="The username of the user", examples=["johndoe"])


class VerifyEmail(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    code: str = Field(..., description="The verification code", examples=["123456"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ OUTPUT MODEL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class Response(BaseModel):
    message: str = Field(..., description="The response message", examples=["ok"])


class Tokens(BaseModel):
    type: str = Field(..., description="The token type", examples=["Bearer"])
    access_token: str = Field(..., description="The access token", examples=["<access_token>"])


class RefreshToken(Tokens):
    refresh_token: str = Field(..., description="The refresh token", examples=["<refresh_token>"])


class LoginResponse(Response):
    tokens: RefreshToken = Field(..., description="The access token and refresh token")


class RefreshResponse(Response):
    tokens: Tokens = Field(..., description="The access token")


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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No token provided")

    if not Authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    access_token = Authorization.split("Bearer ")[1]

    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No token provided")

    try:
        return await handler.verify_access_token(access_token)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
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

    :param user:  The user to register
    :return:  {"message": "ok"}
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
    Verify the email of a user, move the user from email verification pending list to active users.

    :param verify: The email and verification code to verify
    :return: {"message": "ok"}
    """
    try:
        await handler.verify_email(**verify.model_dump())
        return Response(message="ok")
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Validation error: {str(e)}")
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
    Login a user, return the access token and refresh token.

    :param user: The username and password of the user
    :return: {"message": "ok", "tokens": {"access_token": "<access_token>", "refresh_token": "<refresh_token>", "type": "Bearer"}}
    """

    try:
        tokens = await handler.login(**user.model_dump())
        return LoginResponse(message="ok", tokens=RefreshToken(**tokens))
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

    :param Authorization: The Authorization header containing the refresh token.
    :return: {"message": "ok", "tokens": {"access_token": "<access_token>", "type": "Bearer"}}
    """
    try:
        if not Authorization.startswith("Bearer "):
            raise ValueError("Invalid token type")

        refresh_token = Authorization.split("Bearer ")[1]

        new_access_token = await handler.issue_new_access_token(refresh_token)
        return RefreshResponse(message="ok", tokens=Tokens(access_token=new_access_token, type="Bearer"))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")
