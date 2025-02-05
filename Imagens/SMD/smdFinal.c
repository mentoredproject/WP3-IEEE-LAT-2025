#include <pthread.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <pcap.h>

#define BUFSZ 1024

struct client_info {
    int socket;
    struct sockaddr_storage address;
};

int active_rcv_count=0;
int active_snd_count=0;
int passive_rcv_count=0;
int passive_snd_count=0;

char activeSendCount[BUFSZ];
char activeReceiveCount[BUFSZ];
char passiveSendCount[BUFSZ];
char passiveReceiveCount[BUFSZ];

int Qnts_msg=0;
char UDPport[BUFSZ], TCPport[BUFSZ];
char active_snd_log[BUFSZ],active_rcv_log[BUFSZ],passive_snd_log[BUFSZ],passive_rcv_log[BUFSZ];
char output_dir[BUFSZ];

FILE* tcp_micro_sec_log;
//char porta[BUFSZ];

void init_count(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
    	printf("Failed to open the file.\n");
	return;
    }

    fprintf(file, "%d", 0);
    fclose(file);
}

int get_count(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
    	printf("Failed to open the file.\n");
	return -1;
    }

    int count;
    fscanf(file, "%d", &count);
    fclose(file);
    return count;
}

void update_count(const char *filename) {
    int count = get_count(filename);
    
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
    	printf("Failed to open the file.\n");
	return;
    }

    count++;
    fprintf(file, "%d", count);
    fclose(file);
}

void writeToCSV(const char* filename, const char *countFilename) {
    struct timeval currentTimeval;
    gettimeofday(&currentTimeval, NULL);

    FILE* file = fopen(filename, "a");  // Open file in append mode
    if (file == NULL) {
        printf("Failed to open the file.\n");
        return;
    }

    // Convert microseconds to milliseconds for millisecond precision
    long long milliseconds = currentTimeval.tv_usec;

    // Convert the time in seconds to the local time in BRT timezone (GMT-3)
    time_t currentTime = currentTimeval.tv_sec - 3 * 3600;  // GMT-3

    struct tm* timeInfo = localtime(&currentTime);

    // Print timestamp in HH:MM:SS.mmm format (mmm: milliseconds)
    char timeString[50];
    char usec[50];

    strftime(timeString, sizeof(timeString), "%H:%M:%S", timeInfo);

    fprintf(file, "%d,%s,%06lld\n", get_count(countFilename), timeString, milliseconds);

    update_count(countFilename); // Increment the packet number
    
    fclose(file);
}

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header;
    struct in_addr src_addr, dest_addr;

    struct tcphdr *tcp_header;
    const unsigned char *tcp_payload;
    int tcp_payload_length;

    char payload[BUFSZ];
    char tmpstr[BUFSZ];
    bzero(payload,BUFSZ);

    ip_header = (struct ip *)(packet + 14); // Assuming Ethernet frame header is 14 bytes

    unsigned long int seq_number;

    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

        // Calculate the length of the TCP payload
        tcp_payload_length = ntohs(ip_header->ip_len) - ip_header->ip_hl * 4 - tcp_header->th_off * 4;

        // Extract the TCP Sequence Number
        seq_number = ntohl(tcp_header->th_seq);

        // Extract the TCP payload
        tcp_payload = packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4;

        // Print TCP payload data (change this part to log or process the payload as needed)
        //sprintf(outfile, "TCP Payload (Length: %d bytes):\n", tcp_payload_length);
        for (int i = 0; i < tcp_payload_length; i++) {
            sprintf(tmpstr,  "%c", (isprint(tcp_payload[i]) ? tcp_payload[i] : '.'));
            strcat(payload, tmpstr);
            if(i==4)break;
        }
    }

    src_addr = ip_header->ip_src;
    dest_addr = ip_header->ip_dst;

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(src_addr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dest_addr), dest_ip, INET_ADDRSTRLEN);

    fprintf(tcp_micro_sec_log, "%s,%s,%lu,%ld,%ld,%s\n", src_ip, dest_ip, seq_number, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,payload);

    //printf("Source IP: %s\n", src_ip);
    //printf("Destination IP: %s\n", dest_ip);
    
    //printf("Arrival Timestamp: %ld seconds %ld microseconds\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
}

void logexit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void filename_add_ip(char *out_filename, char *in_filename, char *ipstr, char *extension){
    strcpy(out_filename, in_filename);
    strcat(out_filename, "_");
    strcat(out_filename, ipstr);
    strcat(out_filename, extension);
}

void* handle_client(void *arg) {
    struct client_info *cinfo = (struct client_info *)arg; //// Estou passando como argumento
    int csock = cinfo->socket; // O socket
    struct sockaddr_storage address = cinfo->address; // E o endereço de IP do cliente

    // Converter o endereço binário em uma string
    char ipstr[INET6_ADDRSTRLEN];
    if (address.ss_family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&address;
        inet_ntop(AF_INET, &(addr4->sin_addr), ipstr, sizeof(ipstr));
    } else if (address.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&address;
        inet_ntop(AF_INET6, &(addr6->sin6_addr), ipstr, sizeof(ipstr));
    }

    char buf[BUFSZ];
    char buf2[BUFSZ];
    char buf3[BUFSZ];
    char buf4[BUFSZ];
    char* token;


    char thread_passive_rcv_log[BUFSZ];
    filename_add_ip(thread_passive_rcv_log, passive_rcv_log, ipstr, ".csv");

    char thread_passive_snd_log[BUFSZ];
    filename_add_ip(thread_passive_snd_log, passive_snd_log, ipstr, ".csv");

    char thread_passiveReceiveCount[BUFSZ];
    filename_add_ip(thread_passiveReceiveCount, passiveReceiveCount, ipstr, ".txt");

    char thread_passiveSendCount[BUFSZ];
    filename_add_ip(thread_passiveSendCount, passiveSendCount, ipstr, ".txt");

    while(1) {
        bzero(buf, BUFSZ);
        
        read(csock, buf, BUFSZ);
        writeToCSV(thread_passive_rcv_log, thread_passiveReceiveCount);

        printf("<tcp escuta> leu (%s)\n",buf);

        char mensagem[BUFSZ];
        strcpy(mensagem, buf);

        token=strtok(mensagem," ");
        token = strtok(NULL," ");

        if(strncmp(token,"kill",4)==0){
            printf("<tcp escuta> fechou a conexao\n");
            break;
        }
        
        if(strncmp(token,"READ",4)==0){
            token = strtok(NULL,"\0");
            //printf("|%s|",token);
            bzero(buf,BUFSZ);
            strcpy(buf, token);
            if(strlen(buf)<10){
                strcpy(buf,"default str");
            }
            else{
                switch (token[10]){
                    case 'T':
                        strcat(buf," EQUALS 19.9884");
                        break;
                    case 'H':
                        strcat(buf," EQUALS 37.0933");
                        break;
                    case 'L':
                        strcat(buf," EQUALS 2.69964");
                        break;
                    case 'V':
                        strcat(buf," EQUALS 43.24");
                        break;
                    default:
                        strcpy(buf,"default str");
                    break;
                }
            }
        } else {
            //printf("\nERRO\n");
            strcpy(buf,"default str");
        }
        //printf("%s\n",buf);

        // enviar a string para o client
        //aqui meu

        sprintf(buf2,"%d",get_count(thread_passiveSendCount));
        sprintf(buf3,"00000");
        strcat(buf3,buf2);
        sprintf(buf4,"%s ",buf3+strlen(buf2));
        strcat(buf4,buf);

        write(csock, buf4, strlen(buf4));
        writeToCSV(thread_passive_snd_log, thread_passiveSendCount);

        printf("<tcp escuta> escreveu (%s)\n",buf4);  
    }
    close(csock);
    return NULL;

}

void* SMD_communication_passive_thread(void* arg) {
    // thread queescuta mensagens dos outros servidores
    // {{{
    struct sockaddr_storage storage;
    
    uint16_t port = (uint16_t)atoi(TCPport); // unsigned short
    if (port == 0) {
        logexit("port");
    }
    port = htons(port); // host to network short

    struct sockaddr_in *addr4 = (struct sockaddr_in *)(&storage);
    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = INADDR_ANY;
    addr4->sin_port = port;

    int s;
    s = socket(storage.ss_family, SOCK_STREAM, 0);
    if (s == -1) {
        logexit("socket");
    }

    int enable = 1;
    if (0 != setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int))) {
        logexit("setsockopt");
    }

    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if (0 != bind(s, addr, sizeof(storage))) {
        logexit("bind");
    }

    if (0 != listen(s, 10)) {
        logexit("listen");
    }

    while (1) {
        struct sockaddr_storage cstorage;
        struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
        socklen_t caddrlen = sizeof(cstorage);

        int csock = accept(s, caddr, &caddrlen);
        if (csock == -1) {
            //logexit("accept");
            continue;
        }

        pthread_t client_thread;

        struct client_info *cinfo = malloc(sizeof(struct client_info));
        cinfo->socket = csock;
        memcpy(&(cinfo->address), &cstorage, sizeof(cstorage));

        if (pthread_create(&client_thread, NULL, handle_client, cinfo) != 0) {
            perror("Failed to create thread");
            free(cinfo);
        } else {
            pthread_detach(client_thread); // Detach thread to handle cleanup automatically
        }
    }
    close(s);
    return NULL;
}

void* SMD_communication_active_thread(void* arg) {
    // thread que envia mensagens para o outro servidor
    // {{{
    char *IP = (char *)arg; // Recupera o ENDEREÇO de IP passado como argumento
    struct sockaddr_storage storage;

	uint16_t port = (uint16_t)atoi(TCPport); // unsigned short
    if (port == 0) {
        logexit("port");
    }
    port = htons(port); // host to network short

    struct in_addr inaddr4; // 32-bit IP address
    if (inet_pton(AF_INET, IP, &inaddr4)) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&storage;
		addr4->sin_family = AF_INET;
		addr4->sin_port = port;
		addr4->sin_addr = inaddr4;
	}

    sleep(15);
    int veziot=0;
    int vezitem=0;
    char tmpstr[BUFSZ];
    
    char buf[BUFSZ];
    char buf2[BUFSZ];
    char buf3[BUFSZ];
    char buf4[BUFSZ];

    char thread_activeSendCount[BUFSZ];
    filename_add_ip(thread_activeSendCount, activeSendCount, IP, ".txt");

    char thread_activeReceiveCount[BUFSZ];
    filename_add_ip(thread_activeReceiveCount, activeReceiveCount, IP, ".txt");

    char thread_active_snd_log[BUFSZ];
    filename_add_ip(thread_active_snd_log, active_snd_log, IP, ".csv");

    char thread_active_rcv_log[BUFSZ];
    filename_add_ip(thread_active_rcv_log, active_rcv_log, IP, ".csv");

    while(1){
        int s;
        s = socket(storage.ss_family, SOCK_STREAM, 0);
        if (s == -1) {
            logexit("socket");
        }

        struct sockaddr *addr = (struct sockaddr *)(&storage);
        while(1) {
            if (0 != connect(s, addr, sizeof(storage))) {
                sleep(1);
            }
            break;
        }
        printf("*******************\n<tcp envia> conectou\n");

        // envia mensagem
        bzero(buf, sizeof(buf));
        strcpy(buf,"READ SENSOR ");
        veziot=(veziot+1)%15;
        if (veziot<9){// RECOMPILAR
            strcat(buf,"0");
        }
        sprintf(tmpstr,"%d ",veziot+1);
        strcat(buf,tmpstr);
        vezitem=(vezitem+1)%4;
        switch (vezitem){
            case 0:
                strcat(buf,"TEMPERATURE");
                break;
            case 1:
                strcat(buf,"HUMIDITY");
                break;
            case 2:
                strcat(buf,"LUMINANCE");
                break;
            case 3:
                strcat(buf,"VOLTAGE");
                break;
        }
        //aqui meu
        sprintf(buf2,"%d",get_count(thread_activeSendCount));
        sprintf(buf3,"00000");
        strcat(buf3,buf2);
        sprintf(buf4,"%s ",buf3+strlen(buf2));
        strcat(buf4,buf);

        write(s, buf4, strlen(buf4));

        writeToCSV(thread_active_snd_log, thread_activeSendCount);

        printf("<tcp envia> escreveu (%s)\n",buf4);

        // recebe resposta        
        bzero(buf, sizeof(buf));
        size_t cont1=read(s, buf, sizeof(buf));
        writeToCSV(thread_active_rcv_log, thread_activeReceiveCount);

        printf("<tcp envia> leu (%s)\n",buf);

        // envia mensagem de termino da conexao
        bzero(buf, sizeof(buf));
        strcpy(buf,"kill connection");

        sprintf(buf2,"%d",get_count(thread_activeSendCount));
        sprintf(buf3,"00000");
        strcat(buf3,buf2);
        sprintf(buf4,"%s ",buf3+strlen(buf2));
        strcat(buf4,buf);

        //aqui meu
        write(s, buf4, strlen(buf4));

        writeToCSV(thread_active_snd_log, thread_activeSendCount);

        printf("<tcp envia> escreveu (%s)\n",buf4);

        close(s);
        sleep(3);
    }
    // }}}
    return NULL;
}

void* tcp_micro_sec_log_thread(void* arg){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Replace "eth0" with your network interface
    handle = pcap_open_live("eth0", BUFSZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return NULL;
    }

    // Compile the BPF filter expression
    struct bpf_program fp;
    char filter_exp[] = "tcp[13] & 0x08 != 0"; // This filter expression captures only TCP packets

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    // Apply the compiled filter to the capture handle
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return NULL;
    }

    strcat(output_dir,"server.csv");

    tcp_micro_sec_log = fopen(output_dir, "a");  // Open file in append mode
    if (tcp_micro_sec_log == NULL) {
        printf("SNIFFER - Failed to open the file.\n");
        return NULL;
    }

    // Start capturing and processing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    fclose(tcp_micro_sec_log);

    pcap_close(handle);
    return NULL;
}

void usage(int argc, char **argv) {
    printf("usage: %s <UDPport> <TCPport> <IPdoOutroServer> <nome>\n", argv[0]);
    printf("example: %s 50001 50002 10.128.10.10 SMD1\n", argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv) {
    if(argc < 6){
        usage(argc, argv);
    }
    strcpy(UDPport,argv[2]);
    strcpy(TCPport,argv[3]);
    int numServerToConnect = atoi(argv[4]);

    char IP[numServerToConnect][BUFSZ];

    for(int i=0; i<numServerToConnect; i++) {
        strcpy(IP[i],argv[5+i]);
    }

    strcpy(output_dir,"data/Output/Server/");
    strcat(output_dir,argv[1]);

    strcpy(active_snd_log,output_dir);
    strcat(active_snd_log,"activeSend");

    strcpy(active_rcv_log,output_dir);
    strcat(active_rcv_log,"activeRcv");

    strcpy(passive_snd_log,output_dir);
    strcat(passive_snd_log,"passiveSend");

    strcpy(passive_rcv_log,output_dir);
    strcat(passive_rcv_log,"passiveRcv");

     
    strcpy(activeSendCount,output_dir);
    strcat(activeSendCount,"activeSendCount");
    
    char tmp[BUFSZ];
    for(int i=0;i<numServerToConnect;i++) {
        strcpy(tmp, activeSendCount);
        strcat(tmp, "_");
        strcat(tmp, IP[i]);
        strcat(tmp, ".txt");
        init_count(tmp);
    }

    strcpy(activeReceiveCount,output_dir);
    strcat(activeReceiveCount,"activeReceiveCount");
    for(int i=0;i<numServerToConnect;i++) {
        strcpy(tmp, activeReceiveCount);
        strcat(tmp, "_");
        strcat(tmp, IP[i]);
        strcat(tmp, ".txt");
        init_count(tmp);
    }


    strcpy(passiveSendCount,output_dir);
    strcat(passiveSendCount,"passiveSendCount");
    for(int i=0;i<numServerToConnect;i++) {
        strcpy(tmp, passiveSendCount);
        strcat(tmp, "_");
        strcat(tmp, IP[i]);
        strcat(tmp, ".txt");
        init_count(tmp);
    }

    strcpy(passiveReceiveCount,output_dir);
    strcat(passiveReceiveCount,"passiveReceiveCount");
    for(int i=0;i<numServerToConnect;i++) {
        strcpy(tmp, passiveReceiveCount);
        strcat(tmp, "_");
        strcat(tmp, IP[i]);
        strcat(tmp, ".txt");
        init_count(tmp);
    }

    //strcpy(porta,argv[4]);

    // Criar outras threads para  os sokets TCP
    // {{{
    pthread_t active_thread[numServerToConnect];
    pthread_t thread2,thread3;
    int result=0;

    //Server
    for(int i=0; i<numServerToConnect;i++){
        result = pthread_create(&active_thread[i], NULL, SMD_communication_active_thread, IP[i]);
        if (result != 0) {
            // erro ao criar thread
            exit(EXIT_FAILURE);
        }
    }

    result = pthread_create(&thread2, NULL, SMD_communication_passive_thread, NULL);
    if (result != 0) {
        // erro ao criar thread
        exit(EXIT_FAILURE);
    }

    result = pthread_create(&thread3, NULL, tcp_micro_sec_log_thread, NULL);
    if (result != 0) {
        // erro ao criar thread
        exit(EXIT_FAILURE);
    }
    // }}}

    // Usar a thread principal como socket UDP
    // {{{
    struct sockaddr_storage storage;
    
    uint16_t port = (uint16_t)atoi(UDPport); // unsigned short
    if (port == 0) {
        return -1;
    }
    port = htons(port); // host to network short

    struct sockaddr_in *addr4 = (struct sockaddr_in *)(&storage);
    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = INADDR_ANY;
    addr4->sin_port = port;

    int s;
    s = socket(storage.ss_family, SOCK_DGRAM, 0);
    if (s == -1) {
        logexit("socket");
    }

    if (0 != bind(s, (struct sockaddr *)&storage, sizeof(storage))) {
        logexit("bind");
    }

    char buf[BUFSZ];

    while (1) {
        // loop recebe mensagens UDP
        bzero(buf, BUFSZ);
        int nbytes = read(s, buf, BUFSZ);

        // msgs recebidas até agora
        //printf("%d\n",++Qnts_msg);
    }
    close(s);
    // }}}

    // Aguardar a finalização das threads
    // {{{
    for(int i=0;i<numServerToConnect;i++){
        result = pthread_join(active_thread[i], NULL);
        if (result != 0) {
            // erro ao esperar pela thread
            exit(EXIT_FAILURE);
        }
    }
    result = pthread_join(thread2, NULL);
    if (result != 0) {
        // erro ao esperar pela thread
        exit(EXIT_FAILURE);
    }
    result = pthread_join(thread3, NULL);
    if (result != 0) {
        // erro ao esperar pela thread
        exit(EXIT_FAILURE);
    }
    // }}}

    exit(EXIT_SUCCESS);
}
