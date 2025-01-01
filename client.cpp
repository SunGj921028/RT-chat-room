// #include <fcntl.h>
// #include <sys/select.h>
#include <pthread.h>
#include <unistd.h>
#include <netdb.h> // getaddrinfo()

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "defAndFuc.hpp"
#include "myfile.hpp"

using namespace FileProcessing;

char clientMsgBuffer[BUFFER_SIZE] = {0};

bool isLoginReady = false;
bool validSending = true;
bool isSending = false;        //? 當 server 送出選擇訊息後，client 才會進入此模式
bool messageReceived = false;  //? For waiting the server response, and 
bool msgFromClient = false;    //? 當收到來自 client 的訊息後，轉換輸出方式
bool oneClientSending = false; //? 只有一個 client login 時，要印出特殊訊息，並中斷選擇

bool isRejected = false;       //? 當被拒絕連線就不要有任何輸出了
bool isReceivedMsg = false;    //? 當收到 server 的回覆後，才會正常印出下面的內容

bool isReceivingFileMode = false; //? 當收到 server 的回覆後，才會正常印出下面的內容
bool isSendingFileEnd = false;    //? 當送完與接收完檔案後，回到正常的輸出模式並印出 Help 訊息
bool isSendingAudio = false;      //? 判斷是否為音檔傳輸模式
bool isAudioFileContent = false;  //? 判斷是否為音檔內容

pthread_mutex_t mutexReceive = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condReceive = PTHREAD_COND_INITIALIZER;

// 設定最大重試次數和每次重試的延遲時間
#define MAX_RETRIES 10
#define RETRY_DELAY 5  // 延遲 5 秒重試

SSL_CTX* ctx;
SSL* ssl_conn;

string hashValueArray[2] = {"", ""};

bool isFileHashVerified(){
    if(hashValueArray[0] == hashValueArray[1]){
        return true;
    }else{
        return false;
    }
}

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nYou can't press Ctrl + C to end your connection and program\n");
    }
}

// 移除字串前後的空格
static inline string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

int verifyCallback(int preverify_ok, X509_STORE_CTX* ctx) {
    if (!preverify_ok) {
        int error = X509_STORE_CTX_get_error(ctx);
        cerr << "Certificate verification failed: " << X509_verify_cert_error_string(error) << endl;
        return 0;
    }
    return 1;
}

SSL_CTX* initSSL(){
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 載入可信任的 CA 憑證
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", nullptr)) {
        perror("Failed to load CA certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 啟用伺服器證書驗證
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyCallback);

    // 設置安全的加密套件
    const char* cipherList = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384";
    if (!SSL_CTX_set_cipher_list(ctx, cipherList)) {
        perror("Failed to set cipher list");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    return ctx;
}

void verify_server_certificate(SSL* ssl) {
    X509* cert = SSL_get_peer_certificate(ssl); // 獲取伺服器的證書
    if (cert) {
        long res = SSL_get_verify_result(ssl); // 驗證結果
        if (res == X509_V_OK) {
            std::cout << "Server certificate is valid." << std::endl;
        } else {
            std::cerr << "Server certificate verification failed: " << res << std::endl;
            X509_free(cert);
            exit(EXIT_FAILURE); // 結束程式
        }
        X509_free(cert); // 釋放證書
    } else {
        std::cerr << "No server certificate provided." << std::endl;
        exit(EXIT_FAILURE); // 結束程式
    }
}

// 清理 OpenSSL
void cleanupSSL() {
    SSL_CTX_free(ctx);
    ERR_free_strings();
    EVP_cleanup();
}

string filename = "";
ssize_t fileSize = 0;
string targetUserName = "";
vector<vector<string> > fileBuffer;
FILE *audioPipe = nullptr;

void* receiveMessages(void* arg) {
    int clientSocket = *(int*)arg;
    char buffer[BUFFER_SIZE];
    int retries = 0;
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = SSL_read(ssl_conn, buffer, BUFFER_SIZE);
        if (bytesRead <= 0) {
            int sslError = SSL_get_error(ssl_conn, bytesRead);
            if (sslError == SSL_ERROR_WANT_READ || sslError == SSL_ERROR_WANT_WRITE) {
                continue;
            }else if (sslError == SSL_ERROR_ZERO_RETURN) {
                system("clear");
                cout << "\033[33m[Server]: Disconnected.\033[0m" << endl;
            }else if(sslError == SSL_ERROR_SYSCALL){
                int err = errno;
                if (err == ECONNRESET || err == EPIPE) {
                    // 對端已經關閉了連線
                    fprintf(stderr, "Connection reset\n");
                    // 關閉連線、清理資源
                } else {
                    // 其他系統級錯誤
                    retries++;
                    usleep(RETRY_DELAY * 1000000); // 延遲重試，單位為微秒
                    if(retries <= MAX_RETRIES){
                        continue;
                    }else{
                        fprintf(stderr, "SSL syscall error: %s\n", strerror(err));
                    }
                }
            }else if(sslError == SSL_ERROR_SSL){
                cerr << "SSL_read failed due to SSL protocol error." << endl;
            }else{
                cerr << "SSL_read encountered unknown error." << endl;
            }
            break;
        }else{
            retries = 0;
        }

        // Streaming the audio content in real-time
        if(isSendingAudio && strncmp(buffer, "EOF", 3) != 0){
            cout << "Received " << bytesRead << " bytes of audio data." << endl;
            fwrite(buffer, sizeof(char), bytesRead, audioPipe);
        }

        string message(buffer);

        if(message.find("FILE:") != string::npos || message.find("INFO:") != string::npos || message.find("EOF") != string::npos
            || message.find("AUDIOINFO:") != string::npos){
            if(message.find("AUDIOINFO:") != string::npos){ isSendingAudio = true; }
            isReceivingFileMode = true;
            isSendingFileEnd = false;
        }
        
        if(!isReceivingFileMode){
            if(message.find("Client_") != string::npos){
                msgFromClient = true;
            }

            cout << "\r"; // Clear current line
            if(msgFromClient){
                int idx = message.find("_");
                string color = colors[(message[idx + 1] - '0') % colors.size()];
                cout << "\n\n" << color << message << "\033[0m" << endl;
                //! Due to the order of the received message is before the client send something
                printHelp();
                cout << "Enter command: " << flush;
                msgFromClient = false; //? 確保不會重複印出
                isReceivedMsg = true;  //? 在上面的送出後，等待到 client 接收到 server 的回覆，才會正常印出下面的內容
            }else{
                isReceivedMsg = false; //? 確認當前有收到過 server 的回覆
                usleep(400000); // Delay for 1ms
                system("clear");
                cout << "\033[33m[Server]: " << message << "\033[0m" << endl;
                if(message == rejectMsg){
                    SSL_shutdown(ssl_conn);
                    SSL_free(ssl_conn);
                    cleanupSSL();
                    close(clientSocket);
                    isRejected = true;
                    exit(EXIT_FAILURE);
                }
                if(isSendingFileEnd){
                    printHelp();
                    cout << "Enter command: " << flush;
                    isSendingFileEnd = false;
                    isReceivedMsg = true;
                }
            }

            if(message != goodByeMsg && !isReceivedMsg){ //? !isReceivedMsg 確保下面會等待回覆後再繼續輸出
                pthread_mutex_lock(&mutexReceive);
                messageReceived = true;
                pthread_cond_signal(&condReceive);
                pthread_mutex_unlock(&mutexReceive);
            }

            // Make the condition check for the message
            if(message == goodByeMsg){
                SSL_shutdown(ssl_conn);
                SSL_free(ssl_conn);
                close(clientSocket);
                cleanupSSL();
                exit(EXIT_SUCCESS);
            }else if(message == rejectMsg){
                SSL_shutdown(ssl_conn);
                SSL_free(ssl_conn);
                cleanupSSL();
                close(clientSocket);
                isRejected = true;
            }else if(message == logoutMsg){
                isLoginReady = false;
            }else if(message.find("Login successful!") != string::npos){
                isLoginReady = true;
            }else if(message == sendCommandInvalid || 
                    message == invalidCommand ||
                    message.find("Receive failed.") != string::npos || message == invalidSendMsg || 
                    message == invalidInputFormat || message == msgToolong || message == nameToolong ||
                    message == targetNameTooLong || message == pathTooLong){
                validSending = false;
            }else if(message == "Please input the mode for sending message！"){
                isSending = true;
                validSending = true;
            }else if(message == onlyOneClientOnline){
                oneClientSending = true;
            }
        }else{
            if(message.find("INFO:") != string::npos && !isSendingAudio){
                istringstream stream(message);
                stream.ignore(5); // 跳过 "INFO:"
                string bytesLabel = "", separator = "", name = "", hashValue = "";
                ssize_t bytes = 0;
                stream >> bytes >> bytesLabel >> separator;
                getline(stream, name, '|');
                name = trim(name); // 假設有 trim 函數，或使用下面的實作
                // 讀取 hash value，並移除所有空格
                getline(stream, hashValue, '|');
                hashValue = trim(hashValue);
                hashValueArray[0] = string(hashValue); //! store the hash value of sent file
                getline(stream, targetUserName);
                targetUserName = trim(targetUserName);
                filename = name;
                fileSize = bytes;
                cout << "\n\n-----------------------------------------------------------------\n";
                cout << "Receiving file: " << filename << " (" << fileSize << " bytes)" << endl;
            }else if(message == "EOF" && !isSendingAudio){
                isReceivingFileMode = false;
                string fileType = parseFileType(filename);
                //! Store the variable for the current file
                string directory = "clientFile_" + targetUserName;
                if(!ensureFileDirectory(directory)){
                    cerr << "Failed to create client file directory." << endl;
                }
                filename = "received_" + to_string(time(nullptr)) + "_" + filename;
                string filePath = generateFilePath(directory, filename);
                ssize_t totalFileSize = fileSize;
                try {
                    unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                    if (!fileReader) {
                        throw runtime_error("Failed to create file reader for type: " + fileType);
                    }

                    fileReader->openReceiveFile(filePath);
                    fileReader->storeFileContentForClient(fileBuffer);
                    fileReader->openSendFile(filePath); //! open the file for calculating the hash for received file
                    fileReader->calculateFileHash(1);
                    hashValueArray[1] = fileReader->getHash(1);
                    cout << "\nHash value of the received file is: " << hashValueArray[1] << endl;
                    fileReader->close();

                    //! Verify the file hash
                    if(isFileHashVerified()){
                        cout << "File hash is verified, file is transferred correctly." << endl;
                    }else{
                        cout << "File hash is not verified, file is corrupted." << endl;
                        if(remove(filePath.c_str()) == 0){
                            cout << "Corrupted file is removed." << endl;
                        }else{
                            cerr << "Failed to remove the file." << endl;
                        }
                    }
                    
                    // Clear state
                    fileBuffer.clear();
                    fileSize = 0;
                    filename.clear();
                    hashValueArray[0] = "";
                    hashValueArray[1] = "";

                } catch (const exception& e) {
                    cerr << "Error processing file: " << e.what() << endl;
                }
                cout << "\nFile transfer is done.\nAnd file is stored in " << filePath << endl;
                cout << "-----------------------------------------------------------------\n";
                isSendingFileEnd = true;
            }else if(message.find("FILE:") != string::npos){
                //! Store the chunk into the file buffer（The first 5 characters are "FILE:", so just skip them）
                fileBuffer.push_back({message.substr(5)});
            }else if(message.find("AUDIOINFO:") != string::npos){
                isSendingAudio = true;
                istringstream stream(message);
                stream.ignore(10); // 跳过 "AUDIOINFO:"
                //! Message format: "AUDIOINFO:xxx bytes | filename | username"
                ssize_t bytes = 0;
                string bytesLabel = "", separator = "", Audioname = "", targetUserName = "";
                stream >> bytes >> bytesLabel >> separator;
                getline(stream, Audioname, '|');
                Audioname = trim(Audioname);
                // 讀取 hash value，並移除所有空格
                getline(stream, targetUserName, '|');
                targetUserName = trim(targetUserName);
                filename = Audioname;
                fileSize = bytes;
                cout << "\n\n-----------------------------------------------------------------\n";
                cout << "Receiving audio file: " << filename << " (" << fileSize << " bytes)" << endl;
                audioPipe = popen("aplay -", "w");
            }else if(message == "EOF" && isSendingAudio){
                isSendingAudio = false;
                isReceivingFileMode = false;
                pclose(audioPipe);
                cout << "\nAudio file transfer is done and playback completed." << endl;
                cout << "-----------------------------------------------------------------\n";
                isSendingFileEnd = true;
            }
        }
        
    }
    return nullptr;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP_address> <port_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // signal(SIGINT, handle_signal);

    isRejected = false;

    //! Initialize SSL context
    ctx = initSSL();

    //! Server IP and Port
    const char *serverIP = argv[1];
    //? Check if the IP address is valid
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, serverIP, &(sa.sin_addr)) == 0) {
        cerr << "Invalid IP address" << endl;
        cleanupSSL();
        return -1;
    }

    const int portNumber = atoi(argv[2]);
    //? Check if the port number is valid
    if (portNumber <= 0 || portNumber > 65535) {
        cerr << "Invalid port number" << endl;
        cleanupSSL();
        return -1;
    }

    //! Create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        cerr << "Socket creation failed: " << strerror(errno) << endl;
        cleanupSSL();
        return -1;
    }

    //! Set socket options
    int optval = 1;
    if (setsockopt(clientSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        cerr << "Failed to set socket options: " << strerror(errno) << endl;
        close(clientSocket);
        cleanupSSL();
        return -1;
    }

    //! Parse IP address to get the address information
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(serverIP, argv[2], &hints, &res);
    if (status != 0) {
        dprintf(STDERR_FILENO, "getaddrinfo: %s\n", gai_strerror(status));
        close(clientSocket);
        exit(1);
    }

    //! Connect to server with timeout
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;
    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        cerr << "Failed to set receive timeout: " << strerror(errno) << endl;
        close(clientSocket);
        cleanupSSL();
        return -1;
    }

    if (connect(clientSocket, res->ai_addr, res->ai_addrlen) < 0) {
        cerr << "Connection failed: " << strerror(errno) << endl;
        close(clientSocket);
        cleanupSSL();
        return -1;
    }

    cout << "Connected to server at " << serverIP << ":" << portNumber << endl;

    //! Get the client IP and port number that system assigned
    struct sockaddr_in localAddr;
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(clientSocket, (struct sockaddr*)&localAddr, &addrLen) == 0) {
        cout << "Client IP: " << inet_ntoa(localAddr.sin_addr) 
            << ", Client Port Number: " << ntohs(localAddr.sin_port) << endl;
    } else {
        cerr << "Failed to get socket name." << endl;
    }

    //! Create SSL connection
    ssl_conn = SSL_new(ctx);
    SSL_set_fd(ssl_conn, clientSocket);
    if (SSL_connect(ssl_conn) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_conn);
        cleanupSSL();
        exit(EXIT_FAILURE);
    }

    // Add server certificate verification
    verify_server_certificate(ssl_conn);

    cout << "SSL connection established." << endl;

    //! Independent thread for receiving messages and file transfer
    //? Enable the receive thread for receiving messages
    bool isWrongONCreateThread = false;
    pthread_t receiveMsgThread;
    if(pthread_create(&receiveMsgThread, NULL, receiveMessages, (void*)&clientSocket) != 0) {
        cerr << "Failed to create receive message thread." << endl;
        isWrongONCreateThread = true;
    }
    pthread_detach(receiveMsgThread); //! Auto release the thread and resources

    if(isWrongONCreateThread){
        SSL_shutdown(ssl_conn);
        SSL_free(ssl_conn);
        cleanupSSL();
        close(clientSocket);
        exit(EXIT_FAILURE);
    }

    while (1) {
        validSending = true;
        isSending = false;
        oneClientSending = false;

        if(isReceivedMsg){
            continue;
        }
        pthread_mutex_lock(&mutexReceive);
        while(1){
            if(!messageReceived){
                pthread_cond_wait(&condReceive, &mutexReceive);
            }else{
                if(isRejected){ return 0;}
                if(!isSending){
                    printHelp();
                    cout << "Enter command: " << flush;
                }
                messageReceived = false;
                break;
            }
        }
        pthread_mutex_unlock(&mutexReceive);

        
        //! Get the command from client（register, login, send, logout, exit）
        string input;
        getline(cin, input);


        if (input.empty()) continue;

        //! Send the command to server
        if(SSL_write(ssl_conn, input.c_str(), input.length()) < 0) {
            cerr << "Send failed." << endl;
            continue;
        }

        //* For sending movement
        if(input == "send"){
            oneClientSending = false;
            //! If not login, return to the command prompt
            if(!isLoginReady){ continue;}
            
            //! Start to send the mode selection message to server
            string relayMsg = "";
            pthread_mutex_lock(&mutexReceive);
            while(1){
                if(!messageReceived){
                    pthread_cond_wait(&condReceive, &mutexReceive);
                }else{
                    //! Print the sending mode selection
                    printMsgSelection();
                    messageReceived = false;
                    break;
                }
            }
            pthread_mutex_unlock(&mutexReceive);

            if(!isSending){continue;} //! when fail to send the mode selection message, continue

            getline(cin, relayMsg); //? 1, 2, 3, 4, 5, 6

            if(SSL_write(ssl_conn, relayMsg.c_str(), relayMsg.length()) < 0) {
                cerr << "Send failed." << endl;
                continue;
            }

            if((relayMsg != "1" && relayMsg != "2" && relayMsg != "3" && relayMsg != "4" && relayMsg != "5" && relayMsg != "6") || relayMsg.empty()){ continue;}

            //? Receive the response from server
            if(!validSending){continue;}

            //! Send the message with specific format of input
            string input = "";
            pthread_mutex_lock(&mutexReceive);
            while(1){
                if(!messageReceived){
                    pthread_cond_wait(&condReceive, &mutexReceive);
                }else{
                    input = "";
                    if(relayMsg == "1") {
                        //! Client to server of message transfer
                        serverSendMsgSelection();
                        getline(cin, input);
                    } else if (relayMsg == "2") {
                        //! Client to client of message transfer
                        if(oneClientSending){break;}
                        clientSendMsgSelection();
                        getline(cin, input);
                    }else if(relayMsg == "3"){
                        //! Client to server of file transfer
                        clientSendFileToServerSelection();
                        getline(cin, input);
                    }else if(relayMsg == "4"){
                        //! Client to client of file transfer
                        if(oneClientSending){break;}
                        clientSendFileToClientSelection();
                        getline(cin, input);
                    }else if(relayMsg == "5"){
                        //! Client to server of audio transfer
                        clientSendAudioToServerSelection();
                        getline(cin, input);
                    }else if(relayMsg == "6"){
                        if(oneClientSending){break;}
                        clientSendAudioToClientSelection();
                        getline(cin, input);
                    }
                    messageReceived = false;
                    break;
                }
            }
            pthread_mutex_unlock(&mutexReceive);
            if(oneClientSending){continue;} //! When only one client is online, pass below and return to the command prompt

            if(!validSending){ continue;}

            //! Parse the input of message to get username, file path, and file type
            string cmd = "", username = "", filePath = "", fileType = "";
            istringstream iss(input);
            if(relayMsg == "4" || relayMsg == "6"){
                iss >> cmd >> username >> filePath;
                fileType = parseFileType(filePath);
            }else if(relayMsg == "3" || relayMsg == "5"){
                iss >> cmd >> filePath;
                //! Parse the type of file
                fileType = parseFileType(filePath);
            }

            //! Check if the file or command is valid
            bool isValidfile = true;
            bool isValidInput = true;
            if(relayMsg == "3" || relayMsg == "4" || relayMsg == "5" || relayMsg == "6"){
                //? Check if the file is valid
                if(cmd != "send"){
                    cout << "\nInvalid format of command!" << endl;
                    input = fileSelectionFailed;
                    isValidInput = false;
                    messageReceived = true;
                }else if(!isValidFileName(filePath, fileType)){
                    cout << "\nInvalid file!" << endl;
                    input = fileSelectionFailed;
                    isValidfile = false;
                    messageReceived = true;
                }
            }
            //? If valid, send the message to server
            //? If not, send the error message to server and return to the command prompt
            if(SSL_write(ssl_conn, input.c_str(), input.length()) < 0) {
                cerr << "Send failed." << endl;
                continue;
            }
            if(!isValidfile || !isValidInput){continue;}
            if(!validSending){ continue;}

            //! File, Audio transfer
            if(relayMsg == "3" || relayMsg == "4"){
                unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                bool fileReadProc = sendFile(filePath, fileReader, ssl_conn);
                cout << "Hash value of the file " << filePath << " is: " << fileReader->getHash(0) << endl;
                if(!fileReadProc){
                    cout << "\nSomething wrong in the file transfer process !\n";
                }else{
                    cout << "\nFile sent successfully!" << endl;
                }
            }else if(relayMsg == "5" || relayMsg == "6"){
                unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                bool fileReadProc = sendAudioFile(filePath, fileReader, ssl_conn);
                if(!fileReadProc){
                    cout << "\nSomething wrong in the file transfer process !\n";
                }else{
                    cout << "\nFile sent successfully!" << endl;
                }
            }
        }
    }

    close(clientSocket);
    SSL_shutdown(ssl_conn);
    SSL_free(ssl_conn);
    cleanupSSL();
    return 0;
}
