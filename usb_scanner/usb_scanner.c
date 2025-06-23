#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _DEFAULT_SOURCE
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <openssl/sha.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include "../utils/utils.h"

#define MOUNT_DIR "/media"
#define ALT_MOUNT_DIR "/run/media"
#define MAX_PATH 4096
#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)
#define CHANGE_THRESHOLD 10

typedef struct {
    char path[MAX_PATH];
    char hash[HASH_SIZE];
    off_t size;
    mode_t permissions;
    uid_t uid;
    gid_t gid;
    time_t mtime;
} FileEntry;

char *generar_reporte_usb();
void scan_directory(const char *path, FileEntry **out_list, int *out_count);
void compute_sha256(const char *file_path, char *output);
void detect_changes(FileEntry *baseline, int baseline_count, FileEntry *current_files, int current_count, char **buffer, size_t *size);
void alert(char **buffer, size_t *size, const char *message, const char *file);
int is_suspicious_change(const FileEntry *original, const FileEntry *current);
int compare_paths(const void *a, const void *b);

char *generar_reporte_usb() {
    char *buffer = NULL;
    size_t size = 0;
    DIR *dir;
    struct dirent *entry;
    struct stat stat_buf;

    const char *mount_dirs[] = { MOUNT_DIR, ALT_MOUNT_DIR };
    int num_dirs = sizeof(mount_dirs) / sizeof(mount_dirs[0]);

    buffer = agregar_texto(buffer, &size, "==== RESULTADOS DEL ESCANEO DE PUERTOS ====\n\n\n");

    for (int m = 0; m < num_dirs; m++) {
        if ((dir = opendir(mount_dirs[m])) == NULL) {
            continue;
        }

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char mount_path[MAX_PATH];
            snprintf(mount_path, sizeof(mount_path), "%s/%s", mount_dirs[m], entry->d_name);

            // Usar stat para verificar si es directorio
            if (stat(mount_path, &stat_buf) == -1) {
                continue;
            }
            if (!S_ISDIR(stat_buf.st_mode)) {
                continue;
            }

            buffer = agregar_texto(buffer, &size, "Dispositivo conectado detectado en: %s\n", mount_path);

            FileEntry *baseline = NULL;
            int baseline_count = 0;
            scan_directory(mount_path, &baseline, &baseline_count);
            sleep(1);  // Simula tiempo entre escaneos

            FileEntry *current_files = NULL;
            int current_count = 0;
            scan_directory(mount_path, &current_files, &current_count);

            detect_changes(baseline, baseline_count, current_files, current_count, &buffer, &size);

            free(baseline);
            free(current_files);
        }

        closedir(dir);
    }

    buffer = agregar_texto(buffer, &size, "\n===========================================\n");
    return buffer;
}


void scan_directory(const char *path, FileEntry **out_list, int *out_count) {
    DIR *dir;
    struct dirent *entry;
    char full_path[MAX_PATH];

    FileEntry *files = malloc(100 * sizeof(FileEntry));
    int capacity = 100;
    int count = 0;

    if ((dir = opendir(path)) == NULL) return;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        struct stat stat_buf;

        if (lstat(full_path, &stat_buf) == -1) continue;

        if (S_ISDIR(stat_buf.st_mode)) {
            scan_directory(full_path, &files, &count);
        } else if (S_ISREG(stat_buf.st_mode)) {
            if (count >= capacity) {
                capacity *= 2;
                files = realloc(files, capacity * sizeof(FileEntry));
                if (!files) return;
            }

            FileEntry *file = &files[count];
            strncpy(file->path, full_path, MAX_PATH);
            file->size = stat_buf.st_size;
            file->permissions = stat_buf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
            file->uid = stat_buf.st_uid;
            file->gid = stat_buf.st_gid;
            file->mtime = stat_buf.st_mtime;
            compute_sha256(full_path, file->hash);
            count++;
        }
    }
    closedir(dir);
    *out_list = files;
    *out_count = count;
}

void compute_sha256(const char *file_path, char *output) {
    FILE *file = fopen(file_path, "rb");
    if (!file) return;

    SHA256_CTX context;
    SHA256_Init(&context);

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file))) {
        SHA256_Update(&context, buffer, bytes_read);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &context);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[HASH_SIZE - 1] = '\0';
    fclose(file);
}

int compare_paths(const void *a, const void *b) {
    return strcmp(((FileEntry *)a)->path, ((FileEntry *)b)->path);
}

void detect_changes(FileEntry *baseline, int baseline_count, FileEntry *current_files, int current_count, char **buffer, size_t *size) {
    qsort(baseline, baseline_count, sizeof(FileEntry), compare_paths);
    qsort(current_files, current_count, sizeof(FileEntry), compare_paths);

    int i = 0, j = 0;
    int changed = 0;

    while (i < baseline_count || j < current_count) {
        if (i < baseline_count && (j == current_count || strcmp(baseline[i].path, current_files[j].path) < 0)) {
            alert(buffer, size, "Archivo eliminado", baseline[i].path);
            changed++;
            i++;
        } else if (j < current_count && (i == baseline_count || strcmp(baseline[i].path, current_files[j].path) > 0)) {
            alert(buffer, size, "Archivo nuevo detectado", current_files[j].path);
            changed++;
            j++;
        } else {
            if (strcmp(baseline[i].hash, current_files[j].hash) != 0 ||
                baseline[i].size != current_files[j].size ||
                baseline[i].mtime != current_files[j].mtime) {

                alert(buffer, size, "Archivo modificado", current_files[j].path);
                if (is_suspicious_change(&baseline[i], &current_files[j])) {
                    alert(buffer, size, "CAMBIO SOSPECHOSO detectado", current_files[j].path);
                }
                changed++;
            }
            i++;
            j++;
        }
    }

    float percent = (changed * 100.0) / (baseline_count > 0 ? baseline_count : 1);
    if (percent > CHANGE_THRESHOLD) {
        alert(buffer, size, "CAMBIOS MASIVOS detectados en el dispositivo USB", NULL);
    }
}

int is_suspicious_change(const FileEntry *original, const FileEntry *current) {
    if (current->size > original->size * 100) return 1;
    if (current->permissions != original->permissions) return 1;
    if (original->uid != current->uid || original->gid != current->gid) return 1;
    return 0;
}

void alert(char **buffer, size_t *size, const char *message, const char *file) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    if (file) {
        *buffer = agregar_texto(*buffer, size, "[%s] ALERTA: %s\n    Archivo: %s\n", timestamp, message, file);
    } else {
        *buffer = agregar_texto(*buffer, size, "[%s] ALERTA: %s\n", timestamp, message);
    }
}
