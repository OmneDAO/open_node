FROM python:3
LABEL maintainer="MedivolveDAO Foundation <directors@medivolve.foundation>"

# Install dependencies
RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev

# Copy requirements.txt
COPY ./requirements.txt /requirements.txt

# Install all dependencies from requirements.txt
RUN pip3 install -r /requirements.txt

# Copy the application code
COPY ./app /app

# Copy aur.json and pk.json to /app directory
COPY aur.json /app/aur.json
COPY pk.json /app/pk.json

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh

# Ensure entrypoint.sh has execute permissions
RUN chmod +x /entrypoint.sh

# Set the working directory
WORKDIR /app

# Set the PYTHONPATH environment variable
ENV PYTHONPATH=/app

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Set the command to start your application (e.g., your main Python script)
CMD ["python", "open_node.py"]
