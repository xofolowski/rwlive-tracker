# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
#RUN apt-get update && apt-get install -y \
#    build-essential \
#    libssl-dev \
#    libffi-dev \
#    python3-dev \
#    && rm -rf /var/lib/apt/lists/*

# Create a directory for the app
WORKDIR /rwlive-tracker

# Copy the requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY rwlivetracker.py .
RUN chmod 755 rwlivetracker.py
RUN mkdir ./data
RUN mkdir ./conf

# Command to run the application
ENTRYPOINT ["/rwlive-tracker/rwlivetracker.py"]