#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include "../utils/utils.h"

#define MAX_PORT 1024
#define THREAD_POOL_SIZE 64

typedef struct {
    int port;
    const char *service;
} KnownPort;

typedef struct {
    int port;
    int is_open;
    const char *expected_service;
} PortScanResult;

KnownPort known_ports[] = {
    {1, "TCP Port Service Multiplexer"},
    {5, "Remote Job Entry"},
    {7, "Echo"},
    {9, "Discard"},
    {11, "SYSTAT"},
    {13, "Daytime"},
    {17, "Quote of the Day"},
    {19, "Character Generator"},
    {20, "FTP Data"},
    {21, "FTP Control"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {37, "Time"},
    {39, "RLP"},
    {42, "WINS Name Service"},
    {43, "WHOIS"},
    {49, "TACACS"},
    {53, "DNS"},
    {67, "DHCP Server"},
    {68, "DHCP Client"},
    {69, "TFTP"},
    {70, "Gopher"},
    {79, "Finger"},
    {80, "HTTP"},
    {88, "Kerberos"},
    {101, "NIC Host Name"},
    {102, "ISO-TSAP"},
    {107, "Remote Telnet"},
    {109, "POP2"},
    {110, "POP3"},
    {111, "RPCBind"},
    {113, "Ident"},
    {119, "NNTP"},
    {123, "NTP"},
    {135, "Microsoft RPC"},
    {137, "NetBIOS Name Service"},
    {138, "NetBIOS Datagram"},
    {139, "NetBIOS Session"},
    {143, "IMAP"},
    {161, "SNMP"},
    {162, "SNMP Trap"},
    {179, "BGP"},
    {389, "LDAP"},
    {427, "SLP"},
    {443, "HTTPS"},
    {445, "Microsoft DS"},
    {464, "Kerberos Change"},
    {465, "SMTPS"},
    {512, "exec"},
    {513, "login"},
    {514, "shell"},
    {515, "Printer"},
    {520, "RIP"},
    {587, "SMTP (submission)"},
    {631, "IPP (Internet Printing Protocol)"},
    {636, "LDAPS"},
    {873, "rsync"},
    {993, "IMAPS"},
    {995, "POP3S"}
};

int risky_ports[]={23,135,137,138,139,445};
int risky(int port)
{
    for (int i=0; i<7; i++){
        if (risky_ports[i]==port) return 1;
    }
    return 0;
}

const char *known_services[MAX_PORT + 1];
PortScanResult scan_results[MAX_PORT + 1];
pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t port_mutex = PTHREAD_MUTEX_INITIALIZER;
int current_port = 1;

void initialize_known_services() 
{
    for (int i = 0; i <= MAX_PORT; i++) known_services[i] = NULL;
    int count=sizeof(known_ports)/sizeof(KnownPort);
    for (int i=0; i<count; i++){
        known_services[known_ports[i].port]=known_ports[i].service;
    }
}

int scan_port(int port) 
{
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    struct timeval timeout = {.tv_sec = 0, .tv_usec = 50000};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    close(sockfd);
    return result == 0;
}

void *thread_scan(void *arg) 
{
    (void)arg;
    while (1) {
        int port;

        pthread_mutex_lock(&port_mutex);
        if (current_port > MAX_PORT) {
            pthread_mutex_unlock(&port_mutex);
            break;
        }
        port = current_port++;
        pthread_mutex_unlock(&port_mutex);

        int open = scan_port(port);

        pthread_mutex_lock(&results_mutex);
        scan_results[port].port = port;
        scan_results[port].is_open = open;
        scan_results[port].expected_service = known_services[port];
        pthread_mutex_unlock(&results_mutex);
    }
    return NULL;
}

void scan_all_ports() 
{
    current_port=1;
    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&threads[i], NULL, thread_scan, NULL);
    }
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(threads[i], NULL);
    }
}

char *generar_reporte_port()
{
    initialize_known_services();
    scan_all_ports();

    char *reporte = NULL;
    size_t size = 0;
    reporte=agregar_texto(reporte,&size,"==== RESULTADOS DEL ESCANEO DE PUERTOS ====\n\n\n");

    for (int i = 1; i <= MAX_PORT; ++i) {
        const char *service = scan_results[i].expected_service;
        int open = scan_results[i].is_open;
        if (!open) continue;
        if (service) {
            if (risky(i)) reporte=agregar_texto(reporte,&size,"PUERTO (%d) (%s) ABIERTO, VULNERABLE, ALTO RIESGO DE MALWARES!!!\n",i,service);
            else reporte=agregar_texto(reporte,&size,"PUERTO (%d) (%s) ABIERTO ASOCIADO A UN SERVICIO CONOCIDO\n",i,service);
        }
        else {
            reporte=agregar_texto(reporte,&size,"PUERTO (%d) ABIERTO NO ASOCIADO A UN SERVICIO CONOCIDO (POSIBLE AMENAZA)\n",i);
        }
    }
    
    reporte=agregar_texto(reporte,&size,"===========================================\n");
    return reporte;
}