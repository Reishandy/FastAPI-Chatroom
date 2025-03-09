from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, Field, ValidationError
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

import app.handler as handler


#      ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#      ┃                          MODELS                          ┃
#      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
class User(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    password: str = Field(..., description="The password of the user", examples=["password123"])


class Register(User):
    username: str = Field(..., description="The username of the user", examples=["johndoe"])


class VerifyEmail(BaseModel):
    email: str = Field(..., description="The email of the user", examples=["john.doe@example.com"])
    code: str = Field(..., description="The verification code", examples=["123456"])


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
        )]) -> dict[str, str]:
    """
    Register a new user, put the user in email verification pending list.
    Access /verify to verify the email, then the user is moved to the users collection (active users).

    :param user:  The user to register
    :return:  {"message": "ok"}
    """
    try:
        await handler.add_user_to_verification_queue(**user.model_dump())
        return {"message": "ok"}
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
        )]) -> dict[str, str]:
    """
    Verify the email of a user, move the user from email verification pending list to active users.

    :param verify: The email and verification code to verify
    :return: {"message": "ok"}
    """
    try:
        await handler.verify_email(**verify.model_dump())
        return {"message": "ok"}
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Validation error: {str(e)}")
    except ValueError as e:
        if str(e) == "Verification not found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verification not found")

        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal server error: {str(e)}")
