#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "../port_scanner/port_scanner.h"
#include "../process_scanner/process_scanner.h"
#include "../usb_scanner/usb_scanner.h"

GtkTextBuffer *puertos_buffer, *usb_buffer, *procesos_buffer;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// Función para actualizar el contenido del buffer de texto (thread-safe)
void actualizar_buffer(GtkTextBuffer *buffer, const char *texto) {
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    gtk_text_buffer_delete(buffer, &start, &end);
    gtk_text_buffer_set_text(buffer, texto, -1);
}

// Función que será llamada desde el hilo auxiliar para actualizar los textos
gboolean actualizar_pestanas(gpointer data) {
    (void)data;
    pthread_mutex_lock(&lock);
    char *puertos = generar_reporte_port();
    char *usb = generar_reporte_usb();
    char *procesos = generar_reporte_process();

    actualizar_buffer(puertos_buffer, puertos);
    actualizar_buffer(usb_buffer, usb);
    actualizar_buffer(procesos_buffer, procesos);

    free(puertos);
    free(usb);
    free(procesos);
    pthread_mutex_unlock(&lock);
    return G_SOURCE_CONTINUE; // sigue llamándose periódicamente
}

// Crea una pestaña con una GtkTextView
GtkWidget* crear_pestana(const char *titulo, GtkTextBuffer **out_buffer) {
    (void)titulo;
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    GtkWidget *text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), FALSE);

    *out_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);
    return scrolled_window;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "MatCom Guard");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(window), notebook);

    GtkWidget *pestana_puertos = crear_pestana("Puertos", &puertos_buffer);
    GtkWidget *pestana_usb = crear_pestana("USB", &usb_buffer);
    GtkWidget *pestana_procesos = crear_pestana("Procesos", &procesos_buffer);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pestana_puertos, gtk_label_new("Escaneo de Puertos"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pestana_usb, gtk_label_new("Dispositivos USB"));
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pestana_procesos, gtk_label_new("Procesos"));

    gtk_widget_show_all(window);

    // Ejecuta el escaneo automáticamente cada 20 segundos
    g_timeout_add_seconds(10, actualizar_pestanas, NULL);
    actualizar_pestanas(NULL);  // Escaneo inicial inmediato

    gtk_main();
    return 0;
}
