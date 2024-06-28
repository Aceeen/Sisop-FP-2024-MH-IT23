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

## REVISI
discorit.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>


#define PORT 8080
#define MAX_BUFFER 1024
int server_fd;

char username[100];
char password[100];
char channel[100]="";
char room[100]="";


void connect_server() {
    struct sockaddr_in address;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
        perror("invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");
}

int handle_account(const char *buffer) {

    if (buffer == NULL) {
        perror("buffer is empty");
        exit(EXIT_FAILURE);
    }


    if (send(server_fd, buffer, strlen(buffer), 0) < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }

    char response[MAX_BUFFER];
    memset(response, 0, MAX_BUFFER);
    if (recv(server_fd, response, MAX_BUFFER, 0) < 0) {
        perror("recv failed");
        exit(EXIT_FAILURE);
    }
    char *type = strtok(response, ",");
    char *message = strtok(NULL, ",");


    if (strcmp(type, "MSG") == 0){
        printf("%s\n", message);
        return 0;
    }

    else if (strcmp(type, "LOGIN") == 0){
        printf("%s\n", message);
        return 1;
    }
}

int handle_command(const char *buffer) {
  
    if (buffer == NULL) {
        perror("buffer is empty");
        exit(EXIT_FAILURE);
    }
    if (send(server_fd, buffer, strlen(buffer), 0) < 0) {
        perror("send failed");
        exit(EXIT_FAILURE);
    }
    char response[MAX_BUFFER*8];
    memset(response, 0, MAX_BUFFER*8);
    if (recv(server_fd, response, MAX_BUFFER*8, 0) < 0) {
        perror("recv failed");
        exit(EXIT_FAILURE);
    }

    char *type = strtok(response, ",");
    char *message = strtok(NULL, ",");

    if (strcmp(type, "MSG") == 0){
        printf("%s\n", message);
        return 0;
    }

    else if (strcmp(type, "CHANNEL") == 0){
        char *channel_name = strtok(NULL, ",");

        if (channel_name == NULL) {
            perror("channel name is empty");
            exit(EXIT_FAILURE);
        }

        strcpy(channel, channel_name);
        printf("%s\n", message);
        return 0;
    } else if (strcmp(type, "ROOM") == 0){
        char *room_name = strtok(NULL, ",");

        if (room_name == NULL) {
            perror("room name is empty");
            exit(EXIT_FAILURE);
        }

        strcpy(room, room_name);
        printf("%s\n", message);
        return 0;
    }

    else if (strcmp(type, "EXIT") == 0){

        char *exit_type = strtok(NULL, ",");

        if (exit_type == NULL) {
            perror("exit type is empty");
            exit(EXIT_FAILURE);
        }

        if (strcmp(exit_type, "CHANNEL") == 0) {
            memset(channel, 0, 100);
     
            memset(room, 0, 100);
            printf("%s\n", message);
            return 0;
        }

        else if (strcmp(exit_type, "ROOM") == 0) {
            memset(room, 0, 100);
            printf("%s\n", message);
            return 0;
        }
    }


    else if (strcmp(type, "USERNAME") == 0){

        char *new_username = strtok(NULL, ",");

        if (new_username == NULL) {
            perror("new username is empty");
            exit(EXIT_FAILURE);
        }
        strcpy(username, new_username);
        printf("%s\n", message);
        return 0;
    }

    else if (strcmp(type, "KEY") == 0){
        printf("%s\n", message);
        return 1;
    }


    else if (strcmp(type, "QUIT") == 0){
        printf("%s\n", message);
        return 2;
    }
}


void key_request(char *buffer) {

    printf("Enter key: ");

    char key[100];
    memset(key, 0, 100);
    fgets(key, 100, stdin);
    key[strcspn(key, "\n")] = '\0';

    sprintf(buffer, "KEY %s", key);


    handle_command(buffer);
}

int main(int argc, char *argv[]) {

    if (argc < 5) {
        printf("Usage: ./discorit [REGISTER/LOGIN] <username> -p <password>"
               "\n(not enough arguments)");
        return 1;
  } if (strcmp(argv[1], "REGISTER") != 0 && strcmp(argv[1], "LOGIN") != 0) {
        printf("Usage: ./discorit [REGISTER/LOGIN] <username> -p <password>"
               "\n(invalid command)");
        return 1;
  } if (strcmp(argv[3], "-p") != 0) {
        printf("Usage: ./discorit REGISTER <username> -p <password>"
                "\n(missing -p flag)");
        return 1;
    }

    connect_server();


    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    strcpy(username, argv[2]);
    strcpy(password, argv[4]);

 
    if (strcmp(argv[1], "REGISTER") == 0) {

        sprintf(buffer, "REGISTER %s %s", username, password);        



        handle_account(buffer);
        close(server_fd);
        return 0;
    }

    if (strcmp(argv[1], "LOGIN") == 0) {

        sprintf(buffer, "LOGIN %s %s", username, password);

        if (handle_account(buffer) == 1)
        while(1){

            if (strlen(room) > 0) 
                printf("[%s/%s/%s] ", username, channel, room);
            else if (strlen(channel) > 0) 
                printf("[%s/%s] ", username, channel);
            else 
                printf("[%s] ", username);

            memset(buffer, 0, MAX_BUFFER);
            fgets(buffer, MAX_BUFFER, stdin);
            buffer[strcspn(buffer, "\n")] = '\0';

            int res = handle_command(buffer);

            if (res == 2)
                return 0;

            if (res == 1)
                key_request(buffer);
        }
    }
}
```
server.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SERVER_PORT 12345
#define BUF_SIZE 1024
#define MAX_CLIENTS 100
#define LOG_FILE "user.log"

typedef struct {
    int id;
    char name[50];
    unsigned char password_hash[EVP_MAX_MD_SIZE]; 
} User;

typedef struct {
    int id;
    char channel[50];
    unsigned char key_hash[EVP_MAX_MD_SIZE]; 
} Channel;

SSL_CTX *ssl_ctx;

void log_action(const char *action) {
    FILE *file = fopen(LOG_FILE, "a");
    if (file == NULL) {
        perror("Error opening user.log");
        return;
    }
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%d/%m/%Y %H:%M:%S", t);
    fprintf(file, "[%s] %s\n", timestamp, action);
    fclose(file);
}

void load_users(User users[], int *user_count) {
    FILE *file = fopen("users.csv", "r");
    if (file == NULL) {
        perror("Error opening users.csv");
        return;
    }
    *user_count = 0;
    while (fscanf(file, "%d,%49[^,],%*[^,],%60[^,],%9[^\n]\n", &users[*user_count].id, users[*user_count].name, users[*user_count].password_hash, users[*user_count].role) != EOF) {
        (*user_count)++;
    }
    fclose(file);
}

void load_channels(Channel channels[], int *channel_count) {
    FILE *file = fopen("channels.csv", "r");
    if (file == NULL) {
        perror("Error opening channels.csv");
        return;
    }
    *channel_count = 0;
    while (fscanf(file, "%d,%49[^,],%*[^,],%60[^\n]\n", &channels[*channel_count].id, channels[*channel_count].channel, channels[*channel_count].key_hash) != EOF) {
        (*channel_count)++;
    }
    fclose(file);
}

int compute_hash(const char *password, unsigned char *hash) {
    unsigned char salt[16]; // Salt for hashing

    // Generate random salt
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        perror("Error generating salt");
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, salt, sizeof(salt));
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, NULL);

    EVP_MD_CTX_free(mdctx);
    return 0;
}

int authenticate_user(const char *username, const char *password, User users[], int user_count) {
    unsigned char hashed_password[EVP_MAX_MD_SIZE];
    compute_hash(password, hashed_password);

    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].name, username) == 0 && memcmp(users[i].password_hash, hashed_password, EVP_MAX_MD_SIZE) == 0) {
            return users[i].id;
        }
    }
    return -1;
}

void handle_register(SSL *ssl, const char *username, const char *password, User users[], int *user_count) {
    unsigned char hashed_password[EVP_MAX_MD_SIZE];
    char buffer[BUF_SIZE];

    for (int i = 0; i < *user_count; i++) {
        if (strcmp(users[i].name, username) == 0) {
            snprintf(buffer, sizeof(buffer), "%s sudah terdaftar\n", username);
            SSL_write(ssl, buffer, strlen(buffer));
            return;
        }
    }

    if (compute_hash(password, hashed_password) != 0) {
        perror("Error generating password hash");
        snprintf(buffer, sizeof(buffer), "Error generating password hash\n");
        SSL_write(ssl, buffer, strlen(buffer));
        return;
    }

    int id = *user_count + 1;
    const char *role = (id == 1) ? "ROOT" : "USER";
    users[*user_count].id = id;
    strcpy(users[*user_count].name, username);
    memcpy(users[*user_count].password_hash, hashed_password, EVP_MAX_MD_SIZE);
    strcpy(users[*user_count].role, role);
    (*user_count)++;

    FILE *file = fopen("users.csv", "a");
    if (file == NULL) {
        perror("Error opening users.csv");
        return;
    }
    fprintf(file, "%d,%s,", id, username);
    for (int i = 0; i < EVP_MAX_MD_SIZE; ++i) {
        fprintf(file, "%02x", hashed_password[i]);
    }
    fprintf(file, ",%s\n", role);
    fclose(file);

    snprintf(buffer, sizeof(buffer), "%s berhasil register\n", username);
    SSL_write(ssl, buffer, strlen(buffer));
    log_action(buffer);
}

void handle_login(SSL *ssl, const char *username, const char *password, User users[], int user_count) {
    char buffer[BUF_SIZE];
    int user_id = authenticate_user(username, password, users, user_count);
    if (user_id != -1) {
        snprintf(buffer, sizeof(buffer), "%s berhasil Login\n", username);
    } else {
        snprintf(buffer, sizeof(buffer), "Login gagal\n");
    }
    SSL_write(ssl, buffer, strlen(buffer));
}

void handle_list_channels(SSL *ssl, Channel channels[], int channel_count) {
    char buffer[BUF_SIZE] = "";
    for (int i = 0; i < channel_count; i++) {
        strcat(buffer, channels[i].channel);
        if (i < channel_count - 1) {
            strcat(buffer, " ");
        }
    }
    strcat(buffer, "\n");
    SSL_write(ssl, buffer, strlen(buffer));
}

void handle_join_channel(SSL *ssl, const char *channel_name, const char *key, User users[], int user_count, Channel channels[], int channel_count) {
    char buffer[BUF_SIZE];
    int channel_index = -1;
    for (int i = 0; i < channel_count; i++) {
        if (strcmp(channels[i].channel, channel_name) == 0) {
            channel_index = i;
            break;
        }
    }

    if (channel_index == -1) {
        snprintf(buffer, sizeof(buffer), "Channel %s tidak ditemukan\n", channel_name);
        SSL_write(ssl, buffer, strlen(buffer));
        return;
    }

    if (key != NULL) {
        unsigned char hashed_key[EVP_MAX_MD_SIZE];
        compute_hash(key, hashed_key);
        if (memcmp(channels[channel_index].key_hash, hashed_key, EVP_MAX_MD_SIZE) != 0) {
            snprintf(buffer, sizeof(buffer), "Key salah\n");
            SSL_write(ssl, buffer, strlen(buffer));
            return;
        }
    }

    snprintf(buffer, sizeof(buffer), "[user/%s]\n", channel_name);
    SSL_write(ssl, buffer, strlen(buffer));
    log_action(buffer);
}

void handle_client(SSL *ssl, User users[], int user_count, Channel channels[], int channel_count) {
    char buffer[BUF_SIZE];

    while (1) {
        memset(buffer, 0, BUF_SIZE);
        int read_size = SSL_read(ssl, buffer, BUF_SIZE - 1);
        if (read_size <= 0) {
            break;
        }

        char *command = strtok(buffer, " ");
        if (strcmp(command, "REGISTER") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            handle_register(ssl, username, password, users, &user_count);
        } else if (strcmp(command, "LOGIN") == 0) {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            handle_login(ssl, username, password, users, user_count);
        } else if (strcmp(command, "LIST") == 0) {
            char *type = strtok(NULL, " ");
            if (strcmp(type, "Channels") == 0) {
                handle_list_channels(ssl, channels, channel_count);
            }
        } else if (strcmp(command, "JOIN") == 0) {
            char *channel_name = strtok(NULL, " ");
            char *key = strtok(NULL, " ");
            handle_join_channel(ssl, channel_name, key, users, user_count, channels, channel_count);
        } else {
            snprintf(buffer, sizeof(buffer), "Invalid command\n");
            SSL_write(ssl, buffer, strlen(buffer));
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void *connection_handler(void *socket_desc) {
    int client_sock = *(int*)socket_desc;
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_sock);
        SSL_free(ssl);
        return NULL;
    }

    char client_ip[INET_ADDRSTRLEN];
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    getpeername(client_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("Client connected: %s\n", client_ip);

    User users[MAX_CLIENTS];
    int user_count = 0;
    load_users(users, &user_count);

    Channel channels[MAX_CLIENTS];
    int channel_count = 0;
    load_channels(channels, &channel_count);

    handle_client(ssl, users, user_count, channels, channel_count);

    close(client_sock);
    SSL_free(ssl);
    return NULL;
}

int main() {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();


    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }


    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }


    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Error creating socket");
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);


    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        close(server_sock);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }


    if (listen(server_sock, MAX_CLIENTS) < 0) {
        perror("Error listening for connections");
        close(server_sock);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    printf("Server started. Listening on port %d\n", SERVER_PORT);


    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            perror("Error accepting connection");
            continue;
        }

   
        pthread_t thread;
        if (pthread_create(&thread, NULL, connection_handler, (void *)&client_sock) < 0) {
            perror("Error creating thread");
            close(client_sock);
            continue;
        }

        pthread_detach(thread);
    }


    close(server_sock);
    SSL_CTX_free(ssl_ctx);
    return EXIT_SUCCESS;
}


```
Revisi untuk pembuatan channel dan join channel
![Screenshot 2024-06-29 000009](https://github.com/Aceeen/Sisop-FP-2024-MH-IT23/assets/150018995/1da5b966-3d96-4549-ba82-920c8d5a4882)

![Screenshot 2024-06-29 000021](https://github.com/Aceeen/Sisop-FP-2024-MH-IT23/assets/150018995/47c9c762-6506-4423-8954-97e2b482572e)

![Screenshot 2024-06-29 000122](https://github.com/Aceeen/Sisop-FP-2024-MH-IT23/assets/150018995/3a9ae7e8-e045-4c38-a75b-506e4d998d2f)

