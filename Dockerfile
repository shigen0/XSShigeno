# Use the preferred Python base image
FROM python:3.12.2-slim

# Set the working directory in the container
WORKDIR /app

# Copy only the necessary files, excluding __pycache__
COPY . .

# Remove any __pycache__ directories that were copied
RUN find . -name '__pycache__' -type d -exec rm -r {} +

# Install any required packages
RUN pip install --no-cache-dir -r requirements.txt

# Set the default command to run your script, with optional arguments
ENTRYPOINT ["python3", "src/xsshigeno.py"]
