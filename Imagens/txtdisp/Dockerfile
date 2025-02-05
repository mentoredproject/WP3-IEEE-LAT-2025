FROM python:3.9-slim
RUN pip install --pre scapy[basic] --no-cache-dir && mkdir app
RUN apt update && apt install -y tcpdump
COPY txtdispositivo.py /app/IntelLabData2004.py
RUN chmod +x /app/IntelLabData2004.py
WORKDIR app
