FROM python:alpine

WORKDIR /

COPY ./packet_sniffer.py ./protocols.py /

ENTRYPOINT ["python", "/packet_sniffer.py"]
