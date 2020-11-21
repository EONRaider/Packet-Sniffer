FROM python:alpine

WORKDIR /

COPY ./packet_sniffer.py ./protocols.py /

CMD ["python", "/packet_sniffer.py"]
