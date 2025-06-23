#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

char *agregar_texto(char *buffer, size_t *size, const char *formato, ...) {
    va_list args;
    va_start(args, formato);

    char temp[1024];
    vsnprintf(temp, sizeof(temp), formato, args);
    va_end(args);

    size_t nuevo_len = strlen(temp);
    size_t viejo_len = *size;

    char *nuevo_buffer = realloc(buffer, viejo_len + nuevo_len + 1);
    if (!nuevo_buffer) {
        free(buffer);
        return NULL;
    }

    memcpy(nuevo_buffer + viejo_len, temp, nuevo_len + 1); // incluye el '\0'
    *size += nuevo_len;

    return nuevo_buffer;
}
