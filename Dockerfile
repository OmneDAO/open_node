FROM python:3
LABEL maintainer="OmneDAO Foundation <directors@omne.foundation>"

# Install dependencies
RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev

# Copy requirements.txt
COPY ./requirements.txt /requirements.txt

# Install all dependencies from requirements.txt
RUN pip3 install -r /requirements.txt

# Copy the application code
COPY ./app /app

# Set the working directory
WORKDIR /app

# Set the PYTHONPATH environment variable
ENV PYTHONPATH=/app

# Set the command to start your application (e.g., your main Python script)
CMD ["python", "open_node.py"]
