# Build and run with:
# docker build -t sniff . && docker run --network host sniff

FROM python:3.8-alpine
LABEL maintainer="EONRaider (https://github.com/EONRaider)"
ENV PYTHONUNBUFFERED=1
COPY . .
CMD ["python", "packet_sniffer.py"]
