#! /usr/bin/env python3

import sys
from scapy.all import *
from time import sleep, time
from datetime import datetime, timedelta
import io
import re
import subprocess

HOUR = timedelta(hours=1)

def get_source_ip():
    # Run the command
    output = subprocess.check_output(['hostname', '-I'])

    # Decode the output as a string (for Python 3)
    output = output.decode('utf-8')

    # Remove any trailing whitespace or newlines
    output = output.strip()

    return output

def string_hora():
    x = datetime.now()
    x=x-3*HOUR
    return ("%s" %x.strftime("%H:%M:%S.%f"))

def string_data():
    x = datetime.now()
    x=x-3*HOUR
    return ("%s" %x.strftime("%d-%m-%Y"))

if len(sys.argv) != 5:
    print ("usage: %s ip-dst qnts-msg nome-arq nome-log" % sys.argv[0])
    print ("example: %s 1.2.3.4 100 exemplo.txt log.txt" % sys.argv[0])
    exit(1)

#abre arq de log
log = open(sys.argv[4], 'w', buffering=1)

#abre arq
arq = open(sys.argv[3], 'r')
linhas = arq.readlines()
assert len(linhas)>int(sys.argv[2]), "Quantidade de pacotes excede o numero de linhas do arquivo de entrada (n={})".format(len(linhas))
nlinha = 0
intervalo=1

log.write(f"Sequence,Payload,Source_IP,Destination_IP,Time\n")


for linha in linhas:
    nlinha += 1
    temp=re.split("[ \n]", linha)
    payload="%d %s %s %s" %(nlinha, time(), temp[2], temp[3])
    pkt = IP(dst=sys.argv[1])/UDP(dport=50001)/payload
    log.write(f'{nlinha}, {payload},{get_source_ip()}, {sys.argv[1]}, {time()}\n')
    send(pkt)
    if nlinha>=int(sys.argv[2]): break
    sleep(intervalo)
exit(0)
