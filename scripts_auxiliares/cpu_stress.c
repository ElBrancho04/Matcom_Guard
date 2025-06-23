#include <stdio.h>

int main() {
    while(1) {
        // Realiza cálculos sin parar para usar CPU
        double x = 0.0;
        for (int i = 0; i < 1000000; i++) {
            x += i * 0.000001;
        }
    }
    return 0;
}

