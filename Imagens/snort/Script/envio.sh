#!/usr/bin/env bash

SNORT_LOG=$1  # SNORT LOG PATH
SSH_FILE="/ruleShare/ssh_address.json" # IP ADDRESS OF OUTHER SNORT
DIR_RULES="/usr/local/etc/rules/"
SEND_RULES_FILE="/home/user/sendRules/newRules.rules"
# SCRIPT LOG FILE
LOG_DIR=$2 # Diretorio no qual o log será salvo

TIME="$(date +"%m-%d-%y-%T")"
LOG_FILE="$LOG_DIR/envio_log_${TIME}.csv"

# GET ONLY THE IPV4 FROM HOSTNAME
IPS_STRING=$(hostname -I)
MY_IPv4_IPS=( $(grep -oE "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}" <<< "$IPS_STRING") )
while IFS= read -r line || [ -n "$line" ]; do
    # Recupera a chave valor "IP"
    SSH_IP="$(grep -o '"IP": "[^,]*' <<< $line)"
    SSH_IP="$(grep -oE ':.+' <<< $SSH_IP)"
    SSH_IP=${SSH_IP#":"}
    SSH_IP=$(grep -oE "[^\s]+.+" <<< $SSH_IP)
    SSH_IP=${SSH_IP:2}
    SSH_IP=${SSH_IP%'"'}

    # Se o endereço de IP SSH de destino for a minha maquina então esse é o endereço que devo utilizar
    # Para identificar esse snort
    for addr in "${MY_IPv4_IPS[@]}"; do
        if [ "$addr" = "$SSH_IP" ]; then
            MY_IPv4=$addr
            break 2
        fi
    done
done < $SSH_FILE

# LOG FILE HEADER
echo "TIME (HH:MM::SS::NANOSECONDS) ,TIMEZONE, IP ORIGEM, IP DESTINO, REGRA, FORWARDING_FLAG, STATUS" > "$LOG_FILE"

# Numero de Iterações
count=0

while true; do
    tail "$SNORT_LOG" | while read line; do

        # Recupera o ID utilizado na regra
        PROCESS_ID1="$(grep -o "\"rule\" : \"[^\"]*\"" <<< "$line")"
        PROCESS_ID2="$(grep -o ':[[:digit:]]*:' <<< "$PROCESS_ID1")"
        ID="$(grep -o '[[:digit:]]*' <<< "$PROCESS_ID2")"

        #Recupera a regra utilizada
        RULE="$(grep -Erh "^[^\s]+[\s]*[^\s]+[\s]*[^\s]+[\s]*[^\s]+[\s]*->.+sid[\s]*:[\s]*${ID}[\s]*;" $DIR_RULES)"

        # Verifica se a regra já foi enviada para outro snort
        if grep -m 1 "$RULE" "$SEND_RULES_FILE"
        then 
            ((count++))
            echo "Regra já compartilhada, iteração: $count"
            continue
        fi

        # Ao detectar que uma regra foi utilizada
        # O Script irá tentar compartilhar com um outro Snort
        # Com a flag de encaminhamento igual a 1
        FORWARDING_FLAG=1

        # true is shell command and always return 0
        # false always return 1
        # se send_again = 1 então o while deverá ser executado novamente
        # para garantir q pelo menos um dos outros Snort recebeu a regra
        SEND_AGAIN=true

        while $SEND_AGAIN; do

            #Envia a regra para os outros SNORT
            while IFS= read -r line || [ -n "$line" ]; do

                # Recupera a chave valor "user"
                SSH_USER="$(grep -o '"user": "[^,]*' <<< $line)"
                # Remove o user da string
                SSH_USER="$(grep -oE ':.+' <<< $SSH_USER)"
                # Remove os dois pontos
                SSH_USER=${SSH_USER#":"}
                # Remove todos os espaços em branco no inicio da string
                SSH_USER=$(grep -oE "[^\s]+.+" <<< $SSH_USER)
                # Remove as aspas do inicio da string
                SSH_USER=${SSH_USER:2}
                # Remove a aspas no final da string
                SSH_USER=${SSH_USER%'"'}

                # Recupera a chave valor "IP"
                SSH_IP="$(grep -o '"IP": "[^,]*' <<< $line)"
                SSH_IP="$(grep -oE ':.+' <<< $SSH_IP)"
                SSH_IP=${SSH_IP#":"}
                SSH_IP=$(grep -oE "[^\s]+.+" <<< $SSH_IP)
                SSH_IP=${SSH_IP:2}
                SSH_IP=${SSH_IP%'"'}

                # Recupera a chave valor "PATH"
                SSH_PATH="$(grep -o '"path": "[^}]*' <<< $line)"
                SSH_PATH="$(grep -oE ':.+' <<< $SSH_PATH)"
                SSH_PATH=${SSH_PATH#":"}
                SSH_PATH=$(grep -oE "[^\s]+.+" <<< $SSH_PATH)
                SSH_PATH=${SSH_PATH:2}
                SSH_PATH=${SSH_PATH%'"'}

                echo "************ Verificando a Igualdade dos IPS *****************"
                echo "***Envia***    Meu IP: $MY_IPv4"
                echo "***Envia***    IP Dest: $SSH_IP"    

                # Se o endereço de IP SSH de destino for a minha maquina a regra não deve ser enviada
                if [ "$MY_IPv4" = "$SSH_IP" ]; then
                    echo "***Envia***    Os IP's são iguais"   
                    continue 1
                fi

                echo "***Envia***    Os IP's NAO são iguais"  

                # Envia a regra via ssh
                echo "${RULE}, IP_ORIGEM: $MY_IPv4, FORWARDING: $FORWARDING_FLAG" | sshpass -p user ssh -o "StrictHostKeyChecking=no" "${SSH_USER}@${SSH_IP}" 'cat >> "/home/user/receiveRules/newRules.rules"'

                # Verifica se o comando anterior executou corretamente
                return_value="${PIPESTATUS[1]}"

                echo "***Envia***    commmand return status is $return_value"

                if [ "$return_value" == 0 ]
                # Caso o comando tenha dado certo
                # E o codigo de retorno seja zero
                then
                    # Salva a Hora, IP origem, IP destino, regra, status.
                    echo "$(date +"%T:%N"), $(date +"%:z"), ${MY_IPv4}, ${SSH_IP}, $RULE, $FORWARDING_FLAG, SUCESS" >> "$LOG_FILE"

                    # Salva a regra enviada em um arquivo
                    echo "${RULE}" >> $SEND_RULES_FILE

                    # Como o snort conseguiu enviar a regra para pelo menos um outro Snort
                    # Ele pode delegar a tarefa de enviar a regra para os outros para ele
                    SEND_AGAIN=false
                    break 2

                # Caso o comando tenha dado erro
                # E o codigo de retorno seja NON-ZERO
                else
                    # Salva a Hora, IP origem, IP destino, regra, status.
                    echo "$(date +"%T:%N"), $(date +"%:z"), ${MY_IPv4}, ${SSH_IP}, $RULE, $FORWARDING_FLAG, FAIL" >> "$LOG_FILE"
                fi


            done < $SSH_FILE
        done
    done
done

