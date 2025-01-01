#ifndef THREADPOOL_HPP
#define THREADPOOL_HPP

#include <queue>
#include <pthread.h>
#include <vector>
#include <stdexcept>
#include <ctime>
#include <openssl/ssl.h>


using namespace std;

class Server;  // Forward declaration

class ThreadPool {
    private:
        queue<int> jobQueue;                   // 工作佇列，儲存客戶端 socket
        pthread_mutex_t queueMutex;            // 保護佇列的互斥鎖
        pthread_cond_t jobAvailable;           // 任務可用的條件變量
        Server* server;                        // Add reference to server
        bool isRunning;                        // 是否正在運行
        vector<pthread_t> workers;             // Store worker threads
        static void* workerThread(void* arg);  // Worker Thread 函式
        static void handleClient(int clientSocket, Server* server); // 處理客戶端邏輯

    public:
        ThreadPool(int numWorkers, Server* serverPtr);       // 建構函式，初始化 Worker Pool
        ~ThreadPool();
        void addJob(int clientSocket);    // 新增任務
        void shutdown();                  // Add shutdown method
};

#endif
