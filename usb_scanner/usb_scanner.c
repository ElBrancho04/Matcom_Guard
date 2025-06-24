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
#include <unistd.h>
#include "../utils/utils.h"

#define MOUNT_DIR "/media/abraham"
#define ALT_MOUNT_DIR "/run/media"
#define MAX_PATH 4096
#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)
#define CHANGE_THRESHOLD 10
#define MAX_FILE_SIZE (100 * 1024 * 1024)
#define MAX_HASH_BYTES (20 * 1024 * 1024)
#define MAX_DEPTH 10
#define MAX_FILES_PER_SCAN 2000

static int total_files_scanned = 0;

typedef struct {
    char path[MAX_PATH];
    char hash[HASH_SIZE];
    off_t size;
    mode_t permissions;
    uid_t uid;
    gid_t gid;
    time_t mtime;
} FileEntry;

typedef struct {
    char mount_path[MAX_PATH];
    FileEntry *baseline;
    int baseline_count;
    int baseline_capacity;
} BaselineInfo;

#define MAX_DEVICES 10
static BaselineInfo dispositivos[MAX_DEVICES];
static int num_dispositivos = 0;

char *generar_reporte_usb();
void scan_directory(const char *path, FileEntry **out_list, int *out_count, int *capacity, int depth);
void compute_sha256(const char *file_path, char *output, off_t file_size);
void detect_changes(FileEntry *baseline, int baseline_count, FileEntry *current_files, int current_count, char **buffer, size_t *size);
void alert(char **buffer, size_t *size, const char *message, const char *file);
int is_suspicious_change(const FileEntry *original, const FileEntry *current);
int compare_paths(const void *a, const void *b);
BaselineInfo *buscar_o_crear_baseline(const char *mount_path);

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
        if (stat(mount_dirs[m], &stat_buf) == -1 || !S_ISDIR(stat_buf.st_mode)) continue;

        dir = opendir(mount_dirs[m]);
        if (!dir) continue;

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

            char mount_path[MAX_PATH];
            snprintf(mount_path, sizeof(mount_path), "%s/%s", mount_dirs[m], entry->d_name);

            if (stat(mount_path, &stat_buf) == -1 || !S_ISDIR(stat_buf.st_mode)) continue;

            BaselineInfo *info = buscar_o_crear_baseline(mount_path);
            if (!info) continue;

            buffer = agregar_texto(buffer, &size, "Dispositivo detectado: %s\n", mount_path);
            total_files_scanned = 0;

            FileEntry *current_files = NULL;
            int current_count = 0, capacity = 100;
            scan_directory(mount_path, &current_files, &current_count, &capacity, 0);

            detect_changes(info->baseline, info->baseline_count, current_files, current_count, &buffer, &size);

            // Actualizar baseline
            free(info->baseline);
            info->baseline = current_files;
            info->baseline_count = current_count;
            info->baseline_capacity = capacity;
        }

        closedir(dir);
    }

    buffer = agregar_texto(buffer, &size, "\n===========================================\n");
    return buffer;
}

BaselineInfo *buscar_o_crear_baseline(const char *mount_path) {
    for (int i = 0; i < num_dispositivos; i++) {
        if (strcmp(dispositivos[i].mount_path, mount_path) == 0) {
            return &dispositivos[i];
        }
    }

    if (num_dispositivos >= MAX_DEVICES) {
        printf("Máximo número de dispositivos alcanzado.\n");
        return NULL;
    }

    strncpy(dispositivos[num_dispositivos].mount_path, mount_path, MAX_PATH - 1);
    dispositivos[num_dispositivos].baseline = NULL;
    dispositivos[num_dispositivos].baseline_count = 0;
    dispositivos[num_dispositivos].baseline_capacity = 0;
    return &dispositivos[num_dispositivos++];
}

void scan_directory(const char *path, FileEntry **out_list, int *out_count, int *capacity, int depth) {
    if (depth > MAX_DEPTH || total_files_scanned >= MAX_FILES_PER_SCAN) return;
    if (access(path, R_OK | X_OK) == -1) return;

    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    char full_path[MAX_PATH];

    if (!*out_list) {
        *out_list = malloc(*capacity * sizeof(FileEntry));
        if (!*out_list) {
            closedir(dir);
            return;
        }
        *out_count = 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        struct stat stat_buf;
        if (lstat(full_path, &stat_buf) == -1 || S_ISLNK(stat_buf.st_mode)) continue;

        if (S_ISDIR(stat_buf.st_mode)) {
            scan_directory(full_path, out_list, out_count, capacity, depth + 1);
        } else if (S_ISREG(stat_buf.st_mode)) {
            if (stat_buf.st_size > MAX_FILE_SIZE) continue;

            if (*out_count >= *capacity) {
                *capacity *= 2;
                FileEntry *tmp = realloc(*out_list, *capacity * sizeof(FileEntry));
                if (!tmp) {
                    closedir(dir);
                    return;
                }
                *out_list = tmp;
            }

            FileEntry *file = &(*out_list)[*out_count];
            strncpy(file->path, full_path, MAX_PATH - 1);
            file->path[MAX_PATH - 1] = '\0';
            file->size = stat_buf.st_size;
            file->permissions = stat_buf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
            file->uid = stat_buf.st_uid;
            file->gid = stat_buf.st_gid;
            file->mtime = stat_buf.st_mtime;
            compute_sha256(full_path, file->hash, stat_buf.st_size);

            (*out_count)++;
            total_files_scanned++;
            if (total_files_scanned >= MAX_FILES_PER_SCAN) break;
        }
    }

    closedir(dir);
}

void compute_sha256(const char *file_path, char *output, off_t file_size) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        strcpy(output, "ERROR");
        return;
    }

    SHA256_CTX context;
    SHA256_Init(&context);

    unsigned char buffer[4096];
    size_t bytes_read, total_read = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&context, buffer, bytes_read);
        total_read += bytes_read;
        if (total_read > MAX_HASH_BYTES) break;
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

    int i = 0, j = 0, changed = 0;

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
        printf("[%s] %s - %s\n", timestamp, message, file);
    } else {
        *buffer = agregar_texto(*buffer, size, "[%s] ALERTA: %s\n", timestamp, message);
        printf("[%s] %s\n", timestamp, message);
    }
}
