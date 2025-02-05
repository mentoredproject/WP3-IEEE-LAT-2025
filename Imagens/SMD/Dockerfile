FROM alpine
RUN apk update && apk add build-base && mkdir app && apk add tcpdump && apk add libpcap-dev && apk add traceroute
COPY smdFinal.c app/smd.c
RUN cd app && gcc -pthread smd.c -o smd -lpcap && sleep 20
WORKDIR /app
