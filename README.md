# Sisop-FP-2024-MH-IT23

# Anggota Kelompok :
- Acintya Edria Sudarsono (5027231020)
- Aisyah Rahmasari (5027231072)
- Dionisius Marcell Putra Indranto (5027231044)

## Program Discorit.c
Untuk mengambil input dari user dan dikirim ke server.c
```
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

```
![Screenshot 2024-06-28 232633](https://github.com/Aceeen/Sisop-FP-2024-MH-IT23/assets/150018995/61399cdb-44cd-4346-aceb-9fa47f5a65fa)
User pertama mendapatkan role root

![Screenshot 2024-06-28 232655](https://github.com/Aceeen/Sisop-FP-2024-MH-IT23/assets/150018995/5d30695d-d0c6-49e1-8739-e9eacf837410)

Data user disimpan dalam file users.csv


## Program Server.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <crypt.h>
#include <sys/stat.h>
#include <time.h>

#define SERVER_PORT 12345
#define USERS_FILE "DiscorIT/users.csv"
#define SALT "$6$rounds=5000$usesomesillystringforsalt$"  // Example salt for SHA-512

// Function to check if file exists
int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

// Function to create necessary directories and files
void initialize_files() {
    if (!file_exists("DiscorIT")) {
        mkdir("DiscorIT", 0755);
    }

    if (!file_exists(USERS_FILE)) {
        FILE *file = fopen(USERS_FILE, "w");
        if (file == NULL) {
            perror("Failed to create users file");
            exit(EXIT_FAILURE);
        }
        fclose(file);
    }
}

void register_user(int client_sockfd, char *username, char *password) {
    FILE *file = fopen(USERS_FILE, "a+");
    if (!file) {
        perror("Failed to open users file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char existing_username[50];
        sscanf(line, "%*d,%49[^,],%*s,%*s", existing_username);
        if (strcmp(existing_username, username) == 0) {
            send(client_sockfd, "Username already taken\n", 23, 0);
            fclose(file);
            return;
        }
    }

    char *hashed_password = crypt(password, SALT);
    if (hashed_password == NULL) {
        send(client_sockfd, "Error hashing password\n", 23, 0);
        fclose(file);
        return;
    }

    int id = 1;
    fseek(file, 0, SEEK_SET);
    while (fgets(line, sizeof(line), file)) {
        int existing_id;
        sscanf(line, "%d,%*s,%*s,%*s", &existing_id);
        if (existing_id >= id) {
            id = existing_id + 1;
        }
    }

    char *role = (id == 1) ? "ROOT" : "USER";
    fprintf(file, "%d,%s,%s,%s\n", id, username, hashed_password, role);
    fclose(file);

    char response[256];
    sprintf(response, "%s successfully registered\n", username);
    send(client_sockfd, response, strlen(response), 0);
}

void login_user(int client_sockfd, char *username, char *password) {
    FILE *file = fopen(USERS_FILE, "r");
    if (!file) {
        perror("Failed to open users file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        int id;
        char existing_username[50], existing_password[200], role[10];
        sscanf(line, "%d,%49[^,],%199[^,],%9s", &id, existing_username, existing_password, role);

        if (strcmp(existing_username, username) == 0) {
            char *hashed_password = crypt(password, existing_password);  // Use existing hash as salt
            if (hashed_password == NULL) {
                send(client_sockfd, "Error hashing password\n", 23, 0);
                fclose(file);
                return;
            }

            printf("Stored hash: %s\n", existing_password); // Debug log
            printf("Computed hash: %s\n", hashed_password); // Debug log

            if (strcmp(hashed_password, existing_password) == 0) {
                char response[256];
                sprintf(response, "%s successfully logged in\n", username);
                send(client_sockfd, response, strlen(response), 0);
            } else {
                send(client_sockfd, "Incorrect password\n", 19, 0);
            }
            fclose(file);
            return;
        }
    }
    send(client_sockfd, "Username not found\n", 19, 0);
    fclose(file);
}

void *handle_client(void *client_sockfd_ptr) {
    int client_sockfd = *(int *)client_sockfd_ptr;
    char buffer[256];
    while (1) {
        int len = recv(client_sockfd, buffer, sizeof(buffer), 0);
        if (len <= 0) {
            break;
        }
        buffer[len] = '\0';

        char command[10], username[50], password[50];
        if (sscanf(buffer, "%s %s -p %s", command, username, password) == 3) {
            if (strcmp(command, "REGISTER") == 0) {
                register_user(client_sockfd, username, password);
            } else if (strcmp(command, "LOGIN") == 0) {
                login_user(client_sockfd, username, password);
            } else {
                send(client_sockfd, "Invalid command\n", 16, 0);
            }
        } else {
            send(client_sockfd, "Invalid command format\n", 23, 0);
        }
    }
    close(client_sockfd);
    return NULL;
}

int main() {
    initialize_files();

    int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    if (listen(server_sockfd, 5) < 0) {
        perror("Listen failed");
        return 1;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sockfd < 0) {
            perror("Accept failed");
            continue;
        }
        pthread_t client_thread;
        pthread_create(&client_thread, NULL, handle_client, &client_sockfd);
    }

    close(server_sockfd);
    return 0;
}
```
![Screenshot 2024-06-28 232310](https://github.com/Aceeen/Sisop-FP-2024-MH-IT23/assets/150018995/55d4c697-6b6e-4c45-944f-7bb78c88018c)
Program berjalan secara daemon
## Program Monitor.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"

void *receive_messages(void *sockfd_ptr) {
    int sockfd = *(int *)sockfd_ptr;
    char buffer[256];
    while (1) {
        int len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (len > 0) {
            buffer[len] = '\0';
            printf("%s\n", buffer);
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("Usage: ./monitor [USERNAME] -channel [CHANNEL_NAME] -room [ROOM_NAME]\n");
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

    char buffer[256];
    sprintf(buffer, "LOGIN %s -channel %s -room %s", argv[1], argv[3], argv[5]);
    send(sockfd, buffer, strlen(buffer), 0);

    pthread_t recv_thread;
    pthread_create(&recv_thread, NULL, receive_messages, &sockfd);

    while (1) {
        fgets(buffer, sizeof(buffer), stdin);
        send(sockfd, buffer, strlen(buffer), 0);
        if (strncmp(buffer, "EXIT", 4) == 0) {
            break;
        }
    }

    close(sockfd);
    return 0;
}
```
## KENDALA
Masih banyak fitur discorIT yang belum bisa berfungsi dengan benar.
