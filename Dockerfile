FROM python:3.9-slim

WORKDIR /app

COPY . /app

# Install packages
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

#command to run
CMD ["python", "run.py"]
