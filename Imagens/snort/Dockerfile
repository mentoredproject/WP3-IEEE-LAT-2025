FROM samuelbrisio/pulledpork:sshserver

RUN apt update &&\
    apt install -y sshpass &&\
    echo "user:user" | chpasswd

# Cria os diretorios utilizados pelo script e Snort
# Permite que as pastas do script possam ser alteradas via ssh
RUN cd / &&\
    mkdir ruleShare &&\ 
    mkdir tmp/snort &&\
    mkdir home/user/receiveRules &&\
    mkdir home/user/sendRules &&\
    chown user home/user/receiveRules &&\
    chown user home/user/sendRules
            
# Remove os arquivos de configuracao do snort
# e cria um arquivo em branco que irá receber as novas regras
RUN apt update &&\
    apt install tcpdump &&\
    rm /usr/local/etc/snort/snort.lua &&\
    rm /usr/local/etc/rules/pulledpork.rules &&\
    touch /usr/local/etc/rules/ruleUpdate.rules

# Copia os arquivos de configuracao do snort -> Esse arquivo ja vem incluido as regras, acao que o snort deve tomar e o tipo de arquivo de log
# Scripts de compatilhamento
COPY snort.lua /usr/local/etc/snort/snort.lua
COPY snort_without_rules.lua /usr/local/etc/snort/snort_without_rules.lua
COPY Script/envio.sh ruleShare/envio.sh
COPY Script/recebe.sh ruleShare/recebe.sh
COPY Script/ssh_address.json ruleShare/ssh_address.json
COPY Rules/snort3-community.rules /usr/local/etc/rules/pulledpork.rules

