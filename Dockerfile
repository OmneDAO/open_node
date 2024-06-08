FROM python:3
LABEL maintainer="OmneDAO Foundation <directors@omne.foundation>"

# Install dependencies and clean up apt cache
RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements.txt
COPY requirements.txt /requirements.txt

# Install all dependencies from requirements.txt
RUN pip3 install --no-cache-dir -r /requirements.txt

# Copy the entrypoint script
COPY entrypoint.sh /entrypoint.sh

# Ensure entrypoint.sh has execute permissions
RUN chmod +x /entrypoint.sh

# Copy the application code
COPY ./app /app

# Set the working directory
WORKDIR /app

# Set the PYTHONPATH environment variable
ENV PYTHONPATH=/app

# Use bash as the default shell
SHELL ["/bin/bash", "-c"]

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Set the command to start your application
CMD ["python", "open_node.py"]
