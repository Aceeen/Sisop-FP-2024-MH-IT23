#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <crypt.h> // Gunakan crypt.h

#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"

void handle_register(int sockfd, char *username, char *password) {
    char buffer[256];
    sprintf(buffer, "REGISTER %s -p %s", username, password);
    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);
    printf("%s\n", buffer);
}

void handle_login(int sockfd, char *username, char *password) {
    char buffer[256];
    sprintf(buffer, "LOGIN %s -p %s", username, password);
    send(sockfd, buffer, strlen(buffer), 0);
    recv(sockfd, buffer, sizeof(buffer), 0);
    printf("%s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: ./discorit [COMMAND] [USERNAME] -p [PASSWORD]\n");
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        return 1;
    }

    if (strcmp(argv[1], "REGISTER") == 0) {
        handle_register(sockfd, argv[2], argv[4]);
    } else if (strcmp(argv[1], "LOGIN") == 0) {
        handle_login(sockfd, argv[2], argv[4]);
    } else {
        printf("Invalid command\n");
    }

    close(sockfd);
    return 0;
}
