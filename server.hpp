#ifndef SERVER_HPP
#define SERVER_HPP

#include <iostream>
#include <queue>
#include <pthread.h>
#include <netinet/in.h>
#include <string>
#include <cstring>
#include <unistd.h>
#include <map>

//! For SSL / TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_CLIENTS 2
#define MAX_WORKERS 2

using namespace std;

class ThreadPool; // 前向宣告

class Server {
    private:
        int serverFd;                     // 伺服器 socket 描述符
        struct sockaddr_in address;       // 伺服器地址

        int currentClients;               // 當前連線數
        ThreadPool* threadPool;           // ThreadPool 物件

        pthread_mutex_t clientCountMutex; // 用於保護 currentClients 的互斥鎖

        SSL_CTX* ssl_ctx;                 // SSL 上下文

        map<int, SSL*> sslMap;            // 用於儲存每個客戶端的 SSL 連線

        void handleNewConnection();       // 處理新連線的邏輯

        // SSL related private methods
        SSL_CTX* initClientSSL();
        void configureSSL(SSL_CTX* ssl_ctx);
        void cleanupSSL();

    public:
        Server(int port);
        ~Server();
        void start(int port);              // 啟動伺服器
        void decrementClientCount();       // Called when a client disconnects
        SSL_CTX* get_ssl_context() { return ssl_ctx; }  // 獲取 SSL 上下文

        friend class ThreadPool;
};

#endif
