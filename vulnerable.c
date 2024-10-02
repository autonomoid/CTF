// Temporarilly disable ASLR on your system:
// echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
// gcc -o vulnerable vulnerable.c -fstack-protector-all -z execstack -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 8181  // Default port if none is provided
#define BUFFER_SIZE 10    // Vulnerable buffer size

void setup(int port) {
    // Simulate a network service's setup
    printf("Service ready! Listening on port %d\n", port);
}

void menu(int client_socket) {
    char menu_str[] = "1. Send a message\n2. Do nothing\n3. Exit\nSelect menu > ";
    send(client_socket, menu_str, strlen(menu_str), 0);
}

void send_message(int client_socket) {
    char buffer[BUFFER_SIZE];  // Vulnerable buffer
    char message_str[] = "Message: ";
    send(client_socket, message_str, strlen(message_str), 0);

    // Vulnerable: receives more data than buffer size allows
    int bytes_received = recv(client_socket, buffer, 256, 0);  // Vulnerability: buffer overflow
    //buffer[bytes_received] = '\0';  // Null-terminate the buffer

    // Echo the message back to the client
    send(client_socket, "You sent: ", 10, 0);
    send(client_socket, buffer, strlen(buffer), 0);
}

void handle_client(int client_socket) {
    int running = 1;
    while (running) {
        menu(client_socket);
        char choice_str[2];
        recv(client_socket, choice_str, 2, 0);  // Read the client's menu choice
        int choice = atoi(choice_str);

        switch (choice) {
            case 1:
                send_message(client_socket);
                break;
            case 2:
                send(client_socket, "Doing nothing...\n", 17, 0);
                break;
            case 3:
                send(client_socket, "Exiting...\n", 11, 0);
                running = 0;  // Stop the loop and disconnect the client
                break;
            default:
                send(client_socket, "Invalid choice.\n", 16, 0);
        }
    }
    // Disconnect the client by closing the socket after exiting the loop
    close(client_socket);
}

int main(int argc, char *argv[]) {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int port = DEFAULT_PORT;

    // Check if a port is provided as a command-line argument
    if (argc > 1) {
        port = atoi(argv[1]);  // Convert the command-line argument to an integer port number
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number. Please provide a valid port between 1 and 65535.\n");
            exit(EXIT_FAILURE);
        }
    }

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind to the specified port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // Listen on any IP address
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    setup(port);

    // Accept and handle incoming connections in a loop
    while (1) {
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }
        handle_client(client_socket);  // Handle each client
    }

    return 0;
}
