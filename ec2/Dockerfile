# Use a lightweight Python base image to keep the file size small
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install them (caches this step to speed up future builds)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your Streamlit code into the container
COPY dashboard.py .

# Expose Streamlit's default port
EXPOSE 8501

# Command to run the dashboard when the container starts
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]