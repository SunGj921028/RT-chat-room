#include "server.hpp"
#include "ThreadPool.hpp"
#include "defAndFuc.hpp"

using namespace std;

int serverFdTmp;

// signal processing function
void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nServer shutting down...\n");
        closeSocket(serverFdTmp);
        exit(EXIT_FAILURE);
    }
}

//! For SSL / TLS
SSL_CTX* Server::initClientSSL(){
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    SSL_CTX* ssl = SSL_CTX_new(TLS_server_method());
    if (!ssl) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ssl;
}

void Server::configureSSL(SSL_CTX* ssl_ctx){
    // Set the certificate and private key files
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
    cout << "SSL context configured successfully." << endl;
}

void Server::cleanupSSL(){
    ERR_free_strings();
    EVP_cleanup();
}

//! Constructor（Initialize the server）
Server::Server(int port) 
    : serverFd(0), currentClients(0), ssl_ctx(nullptr) {
    pthread_mutex_init(&clientCountMutex, nullptr);

    // Initialize the server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    serverFdTmp = serverFd; //! For signal handler
}

//! Destructor
Server::~Server() {
    if (threadPool) {
        threadPool->shutdown();  // Properly shutdown the thread pool
        delete threadPool;
    }
    
    //! Clean up all SSL connections
    for (auto& pair : sslMap) {
        SSL* ssl = pair.second;
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
    sslMap.clear();
    
    //! Then cleanup SSL context
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    
    cleanupSSL();
    closeSocket(serverFd);
    pthread_mutex_destroy(&clientCountMutex);
}

//! Handle new connections
void Server::handleNewConnection() {
    int connSocketFD;
    struct sockaddr_in clientADDR;
    socklen_t addrlen = sizeof(clientADDR);

    if ((connSocketFD = accept(serverFd, (struct sockaddr*)&clientADDR, &addrlen)) < 0) {
        perror("Connection: Accept failed");
        return;
    }

    //! SSL connection
    SSL * ssl_server = SSL_new(ssl_ctx); //? Every client has its own ssl context
    SSL_set_fd(ssl_server, connSocketFD);

    if (SSL_accept(ssl_server) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_server);
        closeSocket(connSocketFD);
        return;
    }

    //! Check if the number of clients exceeds the limit（MAX_CLIENTS = 10）
    pthread_mutex_lock(&clientCountMutex);
    if (currentClients >= MAX_CLIENTS) {
        pthread_mutex_unlock(&clientCountMutex);
        SSL_write(ssl_server, rejectMsg.c_str(), rejectMsg.size());
        SSL_shutdown(ssl_server);
        SSL_free(ssl_server);
        closeSocket(connSocketFD);
        cout << "Rejected a connection: too many clients." << endl;
        return;
    }else{
        cout << "SSL connection for new client established." << endl << endl;
        SSL_write(ssl_server, sucMsg.c_str(), sucMsg.size());
    }

    currentClients++;
    cout << "--- Current number of clients: " << currentClients << endl;
    pthread_mutex_unlock(&clientCountMutex);

    sslMap[connSocketFD] = ssl_server;   //! Store the SSL connection in the map to manage the SSL connection
    threadPool->addJob(connSocketFD);    //! The accepted client connection will be placed in the task queue in worker pool
}

//! Start the server
void Server::start(int port) {
    // 建立 socket
    if ((serverFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        closeSocket(serverFd);
        errorCaller("--- ERROR on server socket ---");
    }

    // 綁定地址
    if (bind(serverFd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        closeSocket(serverFd);
        errorCaller("--- ERROR on server binding ---");
    }

    // 開始監聽
    if (listen(serverFd, MAX_CLIENTS) < 0) {
        closeSocket(serverFd);
        errorCaller("--- ERROR on server listening ---");
    }
    cout << "\033[34mServer listening on port " << port << " ---(ready)\033[0m" << endl;

    // Initialize OpenSSL
    ssl_ctx = initClientSSL();
    configureSSL(ssl_ctx);

    // Create ThreadPool with reference to this server（Main thread pool）
    threadPool = new ThreadPool(MAX_WORKERS, this);

    // 持續接受客戶端連線
    while (1) {
        handleNewConnection();
    }
}

//! Decrease the current number of clients
void Server::decrementClientCount() {
    pthread_mutex_lock(&clientCountMutex);
    if (currentClients > 0) {
        currentClients--;
    }
    cout << "\n--- Current number of clients: " << currentClients << endl;
    pthread_mutex_unlock(&clientCountMutex);
}

int main(int argc, char *argv[]){
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    //? Get the input argv
    int portNumber = atoi(argv[1]);

    //? Calloc the space for server structure variable
    Server server(portNumber);

    //? Step of server initialization with socket and given port number
    signal(SIGINT, handle_signal);

    server.start(portNumber);
    
    return 0;
}
