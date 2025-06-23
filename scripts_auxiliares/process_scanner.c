
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include "utils.h"


#define NAME_LENGHT 256
#define Max_PROCES 100000
#define RAM_UMBRAL 50
#define CPU_UMBRAL 70

char *reporte=NULL;
size_t size=0;

int pid_guide[Max_PROCES];
long last_cpu[Max_PROCES];
char names[Max_PROCES][NAME_LENGHT];
time_t last_time[Max_PROCES];

static const char *whitelist[] = {
    "gnome-shell",
    "Xorg",
    "xfwm4",
    "compiz",
    "plasmashell",
    "kwin_x11",
    "kwin_wayland",
    "conky",
    "pulseaudio",
    "pipewire",
    "systemd",
    "init",
    "bash",
    "zsh",
    "tmux",
    "screen",
    "ssh",
    "dbus-daemon",
    "chromium-browser",
    "chrome",
    "firefox",
    "alacritty",
    "gnome-terminal-",
    "konsole",
    "terminator",
    "code",           // VSCode
    "kate",
    "gedit",
    "nano",
    "vim",
    "emacs",
    "compiler", 
    "monitor_de_procesos",     
    NULL              
};


long get_total_ram_kb() {
    struct sysinfo mem_info;
    
    if(sysinfo(&mem_info) != 0) {
        perror("Error al obtener información de memoria");
        return 0;
    }
    
    // Convertir de bytes a kilobytes
    return (mem_info.totalram * mem_info.mem_unit) / 1024;
}


struct Proces
{
    char name[NAME_LENGHT];
    int proces_pid;
    long proces_cpu_use;
    int proces_memory_use;
    time_t cpu_time_stamp;
}Proces;

struct Node
{
    struct Proces proces;
    struct  Node *next;
}Node;
struct Node* create_Node(char *name,int pid,long cpu,int  memory,time_t time)
{
    struct Node *NewNode=(struct Node*)malloc(sizeof(struct  Node));

    if(NewNode==NULL)
    {
        printf("Memory allocator failer\n");
        exit(1);
    }

    strncpy(NewNode->proces.name,name,NAME_LENGHT);
    NewNode->proces.name[NAME_LENGHT-1]='\0';

    NewNode->proces.proces_cpu_use=cpu;
    NewNode->proces.proces_memory_use=memory;
    NewNode->proces.proces_pid=pid;
    NewNode->proces.cpu_time_stamp=time;
    NewNode->next=NULL;

    return NewNode;

}

void insert_node(struct Node** head, char *name,int pid,long cpu,int memory,time_t time)
{
    struct Node* NewNode=create_Node(name,pid,cpu,memory,time);
    if(*head==NULL)
    {
        *head=NewNode;
        return;
    }
    struct Node* aux=*head;
    while(aux->next!=NULL)
    {
        aux=aux->next;
    }
    aux->next=NewNode;
}
void delete_by_pid(struct Node** head,int pid)
{
    struct Node* temp=*head;
    struct  Node* prev=NULL;

    while(temp!=NULL && temp->proces.proces_pid!=pid)
    {
        prev=temp;
        temp=temp->next;
    }
    if (temp==NULL)
    {
        return;
    }
    if(prev==NULL)
    {
        *head=temp->next;
    }
    else
    {
        prev->next=temp->next;
    }
    free(temp);
}

void free_list(struct Node** head) {
   
    if (head == NULL || *head == NULL) {
        return; // No hay nada que liberar
    }

    struct Node* current = *head;
    struct Node* next = NULL;
    
    while (current != NULL) {
      
        next = current->next;
        free(current);
        current = next;
    }
    
    *head = NULL; // Asegura que el puntero quede en NULL
}



// Función para verificar si un nombre es numérico (PID)
int is_pid( char *name) {
    while (*name) {
        if (!isdigit(*name)) {
            return 0;
        }
        name++;
    }
    return 1;
}


// Función para obtener el nombre del proceso desde /proc/[pid]/status
void get_process_name(int pid, char *name) {
    char path[NAME_LENGHT];
    FILE *status_file;
    char line[256];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    status_file = fopen(path, "r");
    if (status_file == NULL) {
        strncpy(name, "Unknown", NAME_LENGHT);
        return;
    }

    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "Name:", 5) == 0) {
            char *start = line + 6;
            while (*start == ' ' || *start == '\t') start++;
            char *end = strchr(start, '\n');
            if (end) *end = '\0';
            strncpy(name, start, NAME_LENGHT);
            name[NAME_LENGHT - 1] = '\0';
            fclose(status_file);
            return;
        }
    }

    fclose(status_file);
    strncpy(name, "Unknown", NAME_LENGHT);
}

// Función para obtener el uso de memoria desde /proc/[pid]/statm
void get_process_memory(int pid, int *ram_kb) {
    char path[256];
    FILE *statm_file;
    unsigned long vm_size, resident, shared;
    
    // Construir ruta al archivo statm
    snprintf(path, sizeof(path), "/proc/%d/statm", pid);
    
    // Abrir archivo
    if ((statm_file = fopen(path, "r")) == NULL) {
        *ram_kb = 0;
        return;
    }

    // Leer los tres primeros valores: size resident shared
    if (fscanf(statm_file, "%lu %lu %lu", &vm_size, &resident, &shared) != 3) {
        *ram_kb = 0;
        fclose(statm_file);
        return;
    }

    fclose(statm_file);
    
    // Calcular RAM usada = (resident - shared) * 4 (KB)
    *ram_kb = (resident - shared) * 4;
}



// Función para obtener el uso de CPU desde /proc/[pid]/stat
void get_process_cpu(int pid, long *total_cpu,time_t *t) {
    char path[256];
    FILE *stat_file;
    char line[2048];
    unsigned long utime, stime, cutime, cstime;
    int i;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    if ((stat_file = fopen(path, "r")) == NULL) {
        *total_cpu = 0;
        return;
    }

    if (fgets(line, sizeof(line), stat_file) == NULL) {
        *total_cpu = 0;
        fclose(stat_file);
        return;
    }

    char *token = strtok(line, " ");
    for (i = 1; token != NULL && i < 18; i++) {  // Ahora necesitamos llegar al campo 17
        switch(i) {
            case 14: utime = strtoul(token, NULL, 10); break;
            case 15: stime = strtoul(token, NULL, 10); break;
            case 16: cutime = strtoul(token, NULL, 10); break;
            case 17: cstime = strtoul(token, NULL, 10); break;
        }
        token = strtok(NULL, " ");
    }

    fclose(stat_file);
    
    // Sumar tiempos del proceso + hijos (en jiffies)
    *total_cpu = (int)(utime + stime + cutime + cstime);
    *t=time(NULL);
    
    
}




// Función para obtener todos los procesos y agregarlos a la lista
void get_all_processes(struct Node **head) {
   
    DIR *proc_dir;
    struct dirent *entry;

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("No se pudo abrir /proc");
        exit(1);
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (is_pid(entry->d_name)) {
            int pid = atoi(entry->d_name);
            char name[NAME_LENGHT];
            int  memory_usage;
            long cpu_usage;
            time_t t;

            get_process_name(pid, name);
            get_process_cpu(pid, &cpu_usage,&t);
            get_process_memory(pid, &memory_usage);

            // Insertar en la lista
            insert_node(head, name, pid, cpu_usage, memory_usage,t);
        }
    }

    closedir(proc_dir);
}


// Función para imprimir la lista (útil para verificación)
void print_process_list(struct Node *head) {
    printf("%-20s %-10s %-10s %-10s\n", "Nombre", "PID", "CPU", "Memoria");
    printf("------------------------------------------------\n");
    while (head != NULL) {
        printf("%-20s %-10d %-10ld %-10d KB\n", 
               head->proces.name, 
               head->proces.proces_pid, 
               head->proces.proces_cpu_use, 
               head->proces.proces_memory_use);
        head = head->next;
    }
}

void update_process_info(struct Node **head) {
   
    struct Node *current = *head;
    long total_cpu_diff = 0;
    long total_memory=get_total_ram_kb();

    while (current != NULL) {
        int i=0;
        /*while(whitelist[i]!=NULL)
        {
            if(strcmp(whitelist[i],current->proces.name)==0)
            {
                current=current->next;
                break;
            }
            i++;
        }*/
        time_t current_time = current->proces.cpu_time_stamp;
        int pid = current->proces.proces_pid;
        char *current_name = current->proces.name;
        int found = 0;
        float memory_percent = (current->proces.proces_memory_use * 100.0) / total_memory;
        if(memory_percent>RAM_UMBRAL)
                        {
                            reporte=agregar_texto(reporte,&size,"Proceso exedio el uso de RAM\n");
                            reporte=agregar_texto(reporte,&size,"%-20s %-10d %-10ld %-10d (%.2f%%)\n", 
                                current->proces.name,
                                current->proces.proces_pid,
                                current->proces.proces_cpu_use,
                                current->proces.proces_memory_use,
                                memory_percent);
                        }

        // Verificar si el PID está en pid_guide y si el nombre coincide
        for (int i = 0; i < Max_PROCES; i++) {
            if (pid_guide[i] == pid) {
               
                
                // Si el nombre coincide
                if (strcmp(names[i], current_name) == 0) {
                    // Calcular uso de CPU porcentual (diferencia desde last_cpu)
                    long ticks_por_segundo = sysconf(_SC_CLK_TCK);
                    double cpu_diff = (current->proces.proces_cpu_use - last_cpu[i])/(double)ticks_por_segundo;
                    double time_diff = difftime(current_time, last_time[i]);
                    
                    if (time_diff > 0) {
                        double cpu_percent = (cpu_diff / time_diff) * 100.0 / sysconf(_SC_NPROCESSORS_ONLN);
                        if(cpu_percent>CPU_UMBRAL)
                        {
                            reporte=agregar_texto(reporte,&size,"Proceso exedio el uso de CPU\n");
                            reporte=agregar_texto(reporte,&size,"%-20s %-10d %-10ld %-10d (%.2f%%)\n", 
                                current->proces.name,
                                current->proces.proces_pid,
                                current->proces.proces_cpu_use,
                                current->proces.proces_memory_use,
                                cpu_percent);
                        }
                        // Aquí podrías almacenar cpu_percent si lo necesitas
                    }

                    // Actualizar valores en la lista
                    last_cpu[i] = current->proces.proces_cpu_use;
                    last_time[i] = current_time;
                    strncpy(names[i], current_name, NAME_LENGHT);
                    
                    // Obtener y actualizar memoria (ya está en la estructura)
                    
                    current->proces.proces_memory_use ;
                } else {
                    // PID existe pero nombre no coincide - actualizar todo
                    strncpy(names[i], current_name, NAME_LENGHT);
                    last_cpu[i] = current->proces.proces_cpu_use;
                    last_time[i] = current_time;
                
                }
                break;
            }
        }

        // Si no se encontró el PID, agregarlo a las listas
        if (!found) {
            for (int i = 0; i < Max_PROCES; i++) {
                if (pid_guide[i] == 0) {  // Buscar espacio vacío
                    pid_guide[i] = pid;
                    last_cpu[i] = current->proces.proces_cpu_use;
                    last_time[i] = current_time;
                    strncpy(names[i], current_name, NAME_LENGHT);
                    
                    break;
                }
            }
        }

        current = current->next;
    }
}

char *generar_reporte_process()
{
    setbuf(stdout, NULL);
    struct Node *process_list = NULL;
    reporte=NULL;
    size=0;
    reporte=agregar_texto(reporte,&size,"==== RESULTADOS DEL ESCANEO DE PROCESOS ====\n\n\n");
    get_all_processes(&process_list);
    update_process_info(&process_list);
    free_list(&process_list);
    return reporte;
}