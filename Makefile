CC = gcc
CFLAGS = -g -Wall -Wextra -std=c11 $(shell pkg-config --cflags gtk+-3.0)
LDFLAGS = $(shell pkg-config --libs gtk+-3.0)

OBJ = interface/interface.o \
      port_scanner/port_scanner.o \
      usb_scanner/usb_scanner.o \
      process_scanner/process_scanner.o \
      utils/utils.o

TARGET = matcom_guard

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
