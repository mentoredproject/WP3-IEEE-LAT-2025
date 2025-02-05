#!/usr/bin/env bash

# # Arquivo que irá armazenar os logs do script
LOG_DIR=$1 # Diretorio no qual o log será salvo
TIME="$(date +"%m-%d-%y-%T")"
RECEIVE_LOG_FILE="$LOG_DIR/recebe_log_${TIME}.csv"
SEND_LOG_FILE="$LOG_DIR/encaminhamento_log_${TIME}.csv"

# arquivo que vai receber as novas regras via ssh
NOVA_REGRA="/home/user/receiveRules/newRules.rules"
# Diretorio que contem as regras
DIR_REGRAS="/usr/local/etc/rules/"
# arquivo que incorpora as novas regras
RULE_UPDATE="ruleUpdate.rules"
SSH_FILE="/ruleShare/ssh_address.json" # IP ADDRESS OF OUTHER SNORT

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

# Cabeçalho do arquivo de Log
echo "TIME (HH:MM::SS::NANOSECONDS) ,TIMEZONE, IP ORIGEM, IP DESTINO, ENCAMINHAMENTO ,REGRA, INCORPOU AS REGRAS" > "$RECEIVE_LOG_FILE"
echo "TIME (HH:MM::SS::NANOSECONDS) ,TIMEZONE, IP ORIGEM, IP DESTINO, REGRA, FORWARDING_FLAG, STATUS" > "$SEND_LOG_FILE"

tail -F -n +1 "$NOVA_REGRA" | while read line; do
    #Separa a regra, IP de origem e flag de encaminhamento
    
    #Regex para recuperar a flag de encaminhamento
    FORWARDING_FLAG=$(grep -oE "FORWARDING.+" <<< "$line")

    # Remove da string a parte do FORWARDING FLAG
    line=${line%%", $FORWARDING_FLAG"}
    
    #Regex para recuperar o IP de Origem
    IP_ORIGEM=$(grep -oE "IP_ORIGEM.+" <<< "$line")

    # Remove da string a parte do IP de Origem
    RULE=${line%%"$IP_ORIGEM"}
    RULE=${RULE%', '}

    # Remove a string "IP_ORIGEM"
    IP_ORIGEM=${IP_ORIGEM#"IP_ORIGEM: "}

    # Seleciona somente o valor da flag
    FORWARDING_FLAG=$(grep -oE "[[:digit:]]*" <<< "$FORWARDING_FLAG")

    # Falso se a regra já está presente, True se ela for incluida ao conjunto de regras
    INCORPOROU=false
    # Se ainda não contem a regra
    if ! grep -Rq "$RULE" $DIR_REGRAS; then
        echo "$RULE" >> $DIR_REGRAS$RULE_UPDATE
        INCORPOROU=true
        SNORT_PID=$(pidof snort)
        kill -s SIGHUP $SNORT_PID
        sleep 5
    fi

    echo -e "***Recebe***    A regra foi incorporada: $INCORPOROU"

    # Salva a Hora, IP origem, IP destino, regra.
    echo "$(date +"%T:%N"), $(date +"%:z"), ${IP_ORIGEM}, ${MY_IPv4}, $FORWARDING_FLAG, $RULE, $INCORPOROU" >> $RECEIVE_LOG_FILE


    if [ "$FORWARDING_FLAG" == 1 ]; then
        FORWARDING_FLAG=0
        line_numbers=$(wc -l < "$SSH_FILE")

        # Array utilizado para registrar quais snort a regra deverá ser enviada
        # É utilizado a linha do arquivo para representar o snort
        array=( )
        for i in $(seq 1 "$line_numbers"); do
            array+=("$i")
        done

        SEND_AGAIN=true
        while $SEND_AGAIN; do

            fail_to_send=( )
        
            # Itera sobre cada elemento do array
            for line in "${array[@]}"; do
                SNORT_INFO=$(sed -n "${line}p" "$SSH_FILE")

                # Recupera a chave valor "user"
                SSH_USER="$(grep -o '"user": "[^,]*' <<< $SNORT_INFO)"
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
                SSH_IP="$(grep -o '"IP": "[^,]*' <<< $SNORT_INFO)"
                SSH_IP="$(grep -oE ':.+' <<< $SSH_IP)"
                SSH_IP=${SSH_IP#":"}
                SSH_IP=$(grep -oE "[^\s]+.+" <<< $SSH_IP)
                SSH_IP=${SSH_IP:2}
                SSH_IP=${SSH_IP%'"'}

                # Recupera a chave valor "PATH"
                SSH_PATH="$(grep -o '"path": "[^}]*' <<< $SNORT_INFO)"
                SSH_PATH="$(grep -oE ':.+' <<< $SSH_PATH)"
                SSH_PATH=${SSH_PATH#":"}
                SSH_PATH=$(grep -oE "[^\s]+.+" <<< $SSH_PATH)
                SSH_PATH=${SSH_PATH:2}
                SSH_PATH=${SSH_PATH%'"'}


                # Se o endereço de IP SSH de destino for a minha maquina a regra não deve ser enviada
                if [ "$MY_IPv4" = "$SSH_IP" ]; then
                    continue 1
                fi

                # Se o endereço de IP SSH de destino for igual ao IP de origem a regra não deve ser enviada
                if [ "$IP_ORIGEM" = "$SSH_IP" ]; then
                    continue 1
                fi

                # Envia a regra via ssh
                echo "${RULE}, IP_ORIGEM: ${MY_IPv4[1]}, FORWARDING: $FORWARDING_FLAG" | sshpass -p user ssh -o "StrictHostKeyChecking=no" "${SSH_USER}@${SSH_IP}" 'cat >> "/home/user/receiveRules/newRules.rules"'

                # Verifica se o comando anterior executou corretamente
                return_value="${PIPESTATUS[1]}"
                if [ "$return_value" == 0 ]
                # Caso o comando tenha dado certo
                # E o codigo de retorno seja zero
                then
                    # Salva a Hora, IP origem, IP destino, regra, status.
                    echo "$(date +"%T:%N"), $(date +"%:z"), ${MY_IPv4}, ${SSH_IP}, $RULE, $FORWARDING_FLAG, SUCESS" >> "$SEND_LOG_FILE"

                    # Salva a regra enviada em um arquivo
                    # echo "${RULE}" >> "$SEND_RULES_FILE"

                # Caso o comando tenha dado erro
                # E o codigo de retorno seja NON-ZERO
                else
                    # Salva a Hora, IP origem, IP destino, regra, status.
                    echo "$(date +"%T:%N"), $(date +"%:z"), ${MY_IPv4}, ${SSH_IP}, $RULE, $FORWARDING_FLAG, FAIL" >> "$SEND_LOG_FILE"
                    
                    # Adicione esse snort para ser enviado novamente
                    fail_to_send+=("$line")
                fi
            
            done

            array=( ${fail_to_send[@]} )

            # se o array é vazio então não deve enviar o arquivo
            if [[ ${#array[@]} -eq 0 ]]; then
                # O array está vazio
                SEND_AGAIN=false
            fi

            sleep 0.1

        done
    fi

done

