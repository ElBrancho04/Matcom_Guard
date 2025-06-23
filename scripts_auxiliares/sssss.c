#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>

// Función que consume CPU
void consume_cpu() {
    double x = 0.0;
    while (1) {
        x = sin(x) * tan(x) + 3.14159; // Cálculo intensivo
    }
}

// Función que consume RAM
void consume_ram(size_t mb_to_allocate) {
    size_t bytes_to_allocate = mb_to_allocate * 1024 * 1024;
    char *memory_block = malloc(bytes_to_allocate);
    
    if (memory_block == NULL) {
        perror("Error al asignar memoria");
        exit(1);
    }
    
    // Rellenar la memoria con datos para evitar optimizaciones del compilador
    memset(memory_block, 0xFF, bytes_to_allocate);
    
    printf("RAM: %zu MB asignados\n", mb_to_allocate);
    
    while (1) {
        sleep(1); // Mantener la RAM ocupada
    }
    
    free(memory_block); // Nunca se ejecuta (bucle infinito)
}

int main() {
    printf("🔥 Iniciando consumidor de RAM y CPU...\n");
    
    size_t total_ram_mb;
    printf("Ingrese la cantidad de RAM a consumir (MB): ");
    scanf("%zu", &total_ram_mb);
    
    // Crear un proceso hijo para consumir CPU
    __pid_t pid = fork();
    
    if (pid == 0) {
        // Proceso hijo: consume CPU
        consume_cpu();
    } else {
        // Proceso padre: consume RAM
        consume_ram(total_ram_mb);
    }
    
    return 0;
}