#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MB (1024 * 1024)

int main() {
    size_t size = 1024 * MB; // 1 GB de memoria
    char *memory = malloc(size);

    if (memory == NULL) {
        printf("No se pudo asignar memoria\n");
        return 1;
    }

    for (size_t i = 0; i < size; i++) {
        memory[i] = 'A'; // Escribir en toda la memoria
    }

    printf("Memoria asignada y usada. PID: %d\n", getpid());
    sleep(60); // Mantener el proceso vivo
    free(memory);
    return 0;
}
