# Use the official Python image
FROM python:3.13

# Set the working directory in the container
WORKDIR /code

# Copy requirements.txt first to leverage Docker's cache
COPY ./requirements.txt /code/requirements.txt

# Create a virtual environment
RUN python -m venv /code/venv

# Install dependencies within the virtual environment
RUN /code/venv/bin/pip install --upgrade pip
RUN /code/venv/bin/pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy the rest of the application code
COPY ./app /code/app
COPY .env /code/.env

# Command to run the application
# EDIT THIS HOST AND PORT TO MATCH YOUR ENVIRONMENT
CMD ["/code/venv/bin/fastapi", "run app/api.py", "--host", "192.168.1.99", "--port", "30008"]

# docker build -t chatroom-api .
# docker run -d --name chatroom-api-container --network host --restart always chatroom-api