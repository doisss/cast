FROM ubuntu:latest
ENV API_TOKEN="ghp_1234567890abcdef1234567890abcdef1234"
RUN apt-get update && apt-get install -y curl
ADD app.tar.gz /app
CMD ["python3", "app.py"]
