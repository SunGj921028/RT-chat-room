#include "ThreadPool.hpp"
#include "server.hpp"
#include "UserManager.hpp"
#include "defAndFuc.hpp"
#include "myfile.hpp"

#include <errno.h>     // For errno

char clientMsgBuffer[BUFFER_SIZE] = {0};
char clientMsgBufferForSelection[BUFFER_SIZE] = {0};

// Add mutex for color map
pthread_mutex_t colorMapMutex = PTHREAD_MUTEX_INITIALIZER;
unordered_map<int, string> clientColorMp;
string getColor(int socketNum) {
    pthread_mutex_lock(&colorMapMutex);
    if(clientColorMp.find(socketNum) == clientColorMp.end()){ clientColorMp[socketNum] = colors[socketNum % colors.size()]; }
    pthread_mutex_unlock(&colorMapMutex);
    return clientColorMp[socketNum];
}

// Worker Thread 函式，每個 thread 會執行此函式
void* ThreadPool::workerThread(void* arg) {
    ThreadPool* pool = static_cast<ThreadPool*>(arg);

    while (true) {
        int clientSocket = -1;
        // Get a job from the queue
        pthread_mutex_lock(&pool->queueMutex);
        while (pool->jobQueue.empty() && pool->isRunning) {
            pthread_cond_wait(&pool->jobAvailable, &pool->queueMutex);
        }

        //? Check if we should exit
        if (!pool->isRunning && pool->jobQueue.empty()) {
            pthread_mutex_unlock(&pool->queueMutex);
            break;
        }

        //? Get the job if there is one
        if (!pool->jobQueue.empty()) {
            clientSocket = pool->jobQueue.front();
            pool->jobQueue.pop();
        }
        pthread_mutex_unlock(&pool->queueMutex);

        // Process the job if we got one
        if (clientSocket != -1) {
            handleClient(clientSocket, pool->server);
        }
    }

    return nullptr;
}

// 處理客戶端邏輯
void ThreadPool::handleClient(int clientSocket, Server* server) {
    struct sockaddr_in clientInfoTemp; // Auto delete
    socklen_t addrlenTemp = sizeof(clientInfoTemp);
    string newClientIP = "", newClient;
    if(getpeername(clientSocket, (struct sockaddr*)&clientInfoTemp, &addrlenTemp) == 0){
        cout << getColor(clientSocket) << "New client connected. (Socket: " << clientSocket << ") (IP: " << inet_ntoa(clientInfoTemp.sin_addr) << ", port number: " << ntohs(clientInfoTemp.sin_port) << ")" << "\033[0m" << endl;
    }else{cout << "Wrong on getting peer name.\n";}
    SSL* ssl = server->sslMap[clientSocket];

    while (1) {
        memset(clientMsgBuffer, 0, sizeof(clientMsgBuffer));
        ssize_t bytesRead = SSL_read(ssl, clientMsgBuffer, sizeof(clientMsgBuffer)); //! Keep reading the next message or command from client
        
        // Handle disconnection or errors
        if (bytesRead <= 0) {
            int ssl_err = SSL_get_error(ssl, bytesRead);
            if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                // Connection closed gracefully
                dprintf(STDERR_FILENO, "Client %d disconnected gracefully.\n", clientSocket);
            } else {
                // SSL error
                dprintf(STDERR_FILENO, "SSL read error from client %d: %d\n", clientSocket, ssl_err);
            }
            break;
        }

        string receivedMsg(clientMsgBuffer);
        if(receivedMsg.size() >= BUFFER_SIZE){
            dprintf(STDERR_FILENO, "Client %d sent a message longer than the buffer size.\n", clientSocket);
            continue;
        }
        cout << getColor(clientSocket) << "<Client " << clientSocket << ">: " << "\033[0m" << receivedMsg << endl;

        // Parse command
        istringstream iss(receivedMsg);
        string command;
        iss >> command;

        toLowerCase(command);

        string response;
        string username = "", password = "";

        bool msgSelection = false;

        if (command == "register") {
            iss >> username >> password;

            if (username.empty() || password.empty() || iss.peek() != EOF) { //? Check input parameters
                response = invalidRegister;
            }else if(userManager.isLoggedIn(clientSocket)){
                response = logoutToRegister;
            } else if(username.size() > MAX_USERNAME_LENGTH || password.size() > MAX_PASSWORD_LENGTH){
                response = nameToolong;
            }else if (userManager.registerUser(username, password)) {
                ostringstream oss;
                oss << "Registration successful! Account " << username << " created!";
                response = oss.str();
                userManager.saveUsers(username, password);
            } else {
                response = userNameExist;
            }

        }else if (command == "login") {
            iss >> username >> password;
            if (username.empty() || password.empty() || iss.peek() != EOF) { // ! 長度檢查
                response = "Usage: login <username> <password>";
            }else if(username.size() > MAX_USERNAME_LENGTH || password.size() > MAX_PASSWORD_LENGTH){
                response = nameToolong;
            }else if(userManager.isLoggedIn(clientSocket)){
                response = alreadyLogin;
            }else if(!userManager.isAccountExist(username)){
                response = accNotFound;
            }else if(!userManager.isAccountAvailable(username)){
                response = accountNotAvailable;
            }else if (userManager.loginUser(clientSocket, username, password)) {
                ostringstream oss;
                oss << "Login successful! Welcome " << username << " to the server!";
                response = oss.str();
            } else {
                response = incorrectPwd;
            }

        }else if (command == "logout") {
            if(receivedMsg.size() > 6){
                response = invalidInputFormat;
            }else if (userManager.isLoggedIn(clientSocket)) {
                userManager.logoutUser(clientSocket);
                response = logoutMsg;
            }else {
                response = notLogin;
            }
        }else if (command == "exit") {
            if(receivedMsg.size() > 4){
                response = invalidInputFormat;
            }else if (userManager.isLoggedIn(clientSocket)) {
                response = logoutFirst;
            } else {
                response = goodByeMsg;
                server->sslMap.erase(clientSocket);
                if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                    dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                }
                break;
            }
        }else if (command == "send") {
            if(receivedMsg.size() > 4){
                response = sendCommandInvalid;
                if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                    dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                }
                continue;
            }
            if (!userManager.isLoggedIn(clientSocket)) {
                response = notLogin;
            } else {
                //! First tell the client that the server is ready to receive the message mode selection
                msgSelection = true;
                response = "Please input the mode for sending message！";
                if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                    dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                }

                //! To receive the message option selection（1 or 2 or 3） from client
                memset(clientMsgBufferForSelection, 0, sizeof(clientMsgBufferForSelection));
                ssize_t bytesReadforSelection = SSL_read(ssl, clientMsgBufferForSelection, sizeof(clientMsgBufferForSelection));
                string relayMsg = string(clientMsgBufferForSelection); // 1 or 2
                if(relayMsg.empty() || relayMsg.size() > 1 || (relayMsg != "1" && relayMsg != "2" && relayMsg != "3" && relayMsg != "4" && relayMsg != "5" && relayMsg != "6") ){
                    response = invalidSendOption;
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                    }
                    continue;
                }
                if(bytesReadforSelection > 0){
                    cout << getColor(clientSocket) << "<Client " << clientSocket << ">: " << "\033[0m" << "selected message sending mode: " << relayMsg << endl;
                }else{
                    cerr << "Receive failed." << endl;
                    continue;
                }
                

                //! Decide the response message to send
                string resToSend = "";
                if(relayMsg == "2" || relayMsg == "1"){
                    resToSend = "Request received. Please input your message！";
                }else if(relayMsg == "3"){
                    resToSend = "Request received. Please input the file name or path to send to server！";
                }else if(relayMsg == "4"){
                    resToSend = "Request received. Please input the file name or path to send to specific client！";
                }else if(relayMsg == "5"){
                    resToSend = "Request received. Please input the audio file name or path to send to server！";
                }else if(relayMsg == "6"){
                    resToSend = "Request received. Please input the audio file name or path to send to specific client！";
                }
                if(relayMsg == "2" || relayMsg == "4" || relayMsg == "6"){
                    //! If only one client is online, then don't need to show the list
                    bool multiClientOnline = userManager.countOnlineClients() > 1;
                    if(multiClientOnline){
                        //! Send back a message to client to confirm the selection
                        ostringstream oss;
                        oss << resToSend;
                        oss << userManager.printLoginUserList(clientSocket);
                        response = oss.str();
                    }else{
                        response = onlyOneClientOnline;
                    }
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) { 
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        continue;
                    }
                    if(!multiClientOnline){
                        continue;
                    }
                }else if (relayMsg == "1" || relayMsg == "3" || relayMsg == "5"){
                    response = resToSend;
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        continue;
                    }
                }

                //! Dealing with the message in mode 1, 2, 3, 4, 5, 6
                //? For mode 3, client have to check the file exist or not first and server should get message if it isn't exist and skip the file transfer action.
                char actualMsgBuffer[BUFFER_SIZE] = {0};
                memset(actualMsgBuffer, 0, sizeof(actualMsgBuffer));
                ssize_t actuallBytesRead = SSL_read(ssl, actualMsgBuffer, sizeof(actualMsgBuffer));
                if(actuallBytesRead <= 0){
                    cerr << "Receive failed." << endl;
                    continue;
                }
                string actualMsg(actualMsgBuffer);
                cout << getColor(clientSocket) << "<Client " << clientSocket << ">: " << "\033[0m" << actualMsg << endl;
                
                // If it is file transfer, might get different feedback
                if(relayMsg == "3" || relayMsg == "4" || relayMsg == "5" || relayMsg == "6"){
                    if(actualMsg == fileSelectionFailed){
                        continue;
                    }
                }

                istringstream iss(actualMsg);
                string cmd = "";
                iss >> cmd; // send
                toLowerCase(cmd);
                if(cmd != "send"){
                    response = invalidSendMsg;
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                    }
                    continue;
                }
                if(relayMsg == "1"){
                    //? Mode 1: Send normal message to server
                    string message = "";
                    getline(iss >> ws, message);
                    if(message.empty()){
                        response = emptyMsg;
                    }else if(message.size() > BUFFER_SIZE){
                        response = msgToolong;
                    }else{
                        response = "(Client " + to_string(clientSocket) + ")" + username + ": " + message;
                    }
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        continue;
                    }
                }else if(relayMsg == "2"){
                    //? Mode 2: Send message to specific client
                    string targetUsername = "", message = "";
                    iss >> targetUsername;
                    getline(iss >> ws, message);
                    if(targetUsername.empty()){
                        response = invalidSendMsg;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(message.empty()){
                        response = emptyMsg;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(message.size() > BUFFER_SIZE){
                        response = msgToolong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(targetUsername.size() > MAX_USERNAME_LENGTH){
                        response = targetNameTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    int targetClientSocket = userManager.getClientSocketNumFromStatus(targetUsername);
                    if(targetClientSocket == -1){
                        // Send the message to the client who sent the message
                        response = "[Server]: Can't find the target client.";
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else{
                        //! Get the SSL pointer of the target client
                        SSL* targetSSL = server->sslMap[targetClientSocket];
                        // Send the message to the client who sent the message
                        response = "You sent message to " + targetUsername + ": " + message;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        // Send message to target client
                        string targetResponse = "[Client_" + to_string(clientSocket) + " " + userManager.getClientUsername(clientSocket) + "]: " + message;
                        if (SSL_write(targetSSL, targetResponse.c_str(), targetResponse.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", targetClientSocket);
                        }
                    }
                }else if (relayMsg == "3"){
                    //? Mode 3: File transferring for client-to-server
                    // Get the file path from the client input
                    string filePath = "";
                    getline(iss >> ws, filePath);
                    if(filePath.empty()) { //? Check if the file path is empty
                        response = invalidSendMsg;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    if(filePath.size() > MAX_FILEPATH) { //? Check if the file path is too long
                        response = pathTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }

                    // Extract filename from path
                    string filename = filePath.substr(filePath.find_last_of("/\\") + 1); // xxx.txt
                    if(filename.empty()){ //? Check if the filename is empty
                        response = invalidFileName;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    // Ensure the server file directory exists
                    if(!ensureFileDirectory("serverFile")){
                        response = "Failed to create server file directory.";
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    // Get file type
                    string fileType = parseFileType(filename);
                    // Create the file path to save the received file
                    filename = "received_" + to_string(time(nullptr)) + "_" + filename;
                    string serverFilePath = generateFilePath("serverFile", filename);  // Prefix to avoid conflicts

                    try {
                        // Create file reader for receiving
                        unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                        
                        cout << "\nReady to receive file: " + filename << endl;

                        // Call the file receiving function
                        bool fileReceiveProc = receiveFileServer(serverFilePath, fileReader, ssl);
                        if(!fileReceiveProc){
                            throw runtime_error("Something wrong in the file receiving process !");
                        }else{
                            response = "File received successfully and saved at: " + serverFilePath;
                        }

                        // Send the feedback to the client
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }

                    } catch (const exception& e) {
                        response = "Error receiving file: " + string(e.what());
                        if (remove(serverFilePath.c_str()) != 0) {
                            cerr << "Failed to delete incomplete file: " << serverFilePath << endl;
                        } // Delete the file that failed to receive
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            int sslError = SSL_get_error(ssl, -1);
                            if (sslError != SSL_ERROR_WANT_WRITE) {
                                dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                                break;
                            }
                        }
                    }
                }else if(relayMsg == "5"){
                    //? Mode 5: Audio transferring and streaming for client-to-server
                    string filePath = "";
                    getline(iss >> ws, filePath);
                    if(filePath.empty()) { //? Check if the file path is empty
                        response = invalidSendMsg;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    if(filePath.size() > MAX_FILEPATH) { //? Check if the file path is too long
                        response = pathTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }

                    // Extract filename from path
                    string filename = filePath.substr(filePath.find_last_of("/\\") + 1); // xxx.txt
                    if(filename.empty()){ //? Check if the filename is empty
                        response = invalidFileName;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }

                    // Get file type
                    string fileType = parseFileType(filename);

                    try {
                        // Create file reader for receiving
                        unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                        
                        cout << "\nReady to receive and playback audio file: " + filename << endl;

                        // Call the file receiving function
                        bool fileReceiveProc = receiveAndPlayAudioFileServer(fileReader, ssl);
                        if(!fileReceiveProc){
                            throw runtime_error("Something wrong in the file receiving process !");
                        }else{
                            response = "Complete streaming audio file: " + filename;
                        }

                        // Send the feedback to the client
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        // cout << "send msg complete" << endl;

                    } catch (const exception& e) {
                        response = "Error receiving file: " + string(e.what());
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            int sslError = SSL_get_error(ssl, -1);
                            if (sslError != SSL_ERROR_WANT_WRITE) {
                                dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                                break;
                            }
                        }
                    }
                }else if(relayMsg == "4"){
                    //? Mode 4: File transferring for client-to-client
                    string username = "", filePath = "";
                    iss >> username >> filePath;
                    if(username.empty() || filePath.empty()){
                        response = invalidSendMsg;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(filePath.size() > MAX_FILEPATH){
                        response = pathTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(username.size() > MAX_USERNAME_LENGTH){
                        response = targetNameTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }

                    // Extract filename from path
                    string filename = filePath.substr(filePath.find_last_of("/\\") + 1); // xxx.txt
                    if(filename.empty()){ //? Check if the filename is empty
                        response = invalidFileName;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    // Get file type
                    string fileType = parseFileType(filename);
                    
                    if(!isValidFileName(filePath, fileType)){ //? Check if the file name is valid
                        response = invalidFileName;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    string nowUserName = userManager.getClientUsername(clientSocket);
                    int targetClientSocket = userManager.getClientSocketNumFromStatus(username);
                    if(targetClientSocket == -1){
                        // Send the message to the client who sent the message
                        response = "[Server]: Can't find the target client.";
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    SSL* targetSSL = server->sslMap[targetClientSocket];
                    try{
                        unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                        bool fileTransferProc = reTransferFile(fileReader, ssl, targetSSL, filename, username);
                        if(!fileTransferProc){
                            throw runtime_error("Something wrong in the file transferring process !");
                        }else{
                            response = "File received and re-sending complete.";
                        }
                    } catch (const exception& e) { 
                        response = "Error receiving file: " + string(e.what());
                    }
                    // Send confirmation message to the client who want to send file to other client
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                    }
                    response = nowUserName + " sent a file " + "called " + filename + " to you.";
                    if(SSL_write(targetSSL, response.c_str(), response.length()) <= 0){
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", targetClientSocket);
                    }
                }else if(relayMsg == "6"){
                    string username = "", filePath = "";
                    iss >> username >> filePath;
                    if(username.empty() || filePath.empty()){
                        response = invalidSendMsg;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(filePath.size() > MAX_FILEPATH){
                        response = pathTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }else if(username.size() > MAX_USERNAME_LENGTH){
                        response = targetNameTooLong;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    string filename = filePath.substr(filePath.find_last_of("/\\") + 1); // xxx.txt
                    if(filename.empty()){ //? Check if the filename is empty
                        response = invalidFileName;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    // Get file type
                    string fileType = parseFileType(filename);
                    if(!isValidFileName(filePath, fileType)){ //? Check if the file name is valid
                        response = invalidFileName;
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }

                    string nowUserName = userManager.getClientUsername(clientSocket);
                    int targetClientSocket = userManager.getClientSocketNumFromStatus(username);
                    if(targetClientSocket == -1){
                        // Send the message to the client who sent the message
                        response = "[Server]: Can't find the target client.";
                        if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                            dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                        }
                        continue;
                    }
                    SSL* targetSSL = server->sslMap[targetClientSocket];

                    try{
                        unique_ptr<FileProcessing::FileReader> fileReader = FileProcessing::createFileReader(fileType);
                        bool fileTransferProc = reTransferAudioFile(fileReader, ssl, targetSSL, filename, username);
                        if(!fileTransferProc){
                            throw runtime_error("Something wrong in the file transferring process !");
                        }else{
                            response = "Audio file received and re-sending complete.";
                        }
                    } catch (const exception& e) { 
                        response = "Error receiving file: " + string(e.what());
                    }
                    // Send confirmation message to the client who want to send file to other client
                    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                    }
                    response = nowUserName + " sent a audio file " + "called " + filename + " to you.";
                    if(SSL_write(targetSSL, response.c_str(), response.length()) <= 0){
                        dprintf(STDERR_FILENO, "SSL write error to client %d\n", targetClientSocket);
                    }
                }
            }
        }else {
            response = invalidCommand;
        }

        if(!msgSelection){
            if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
                dprintf(STDERR_FILENO, "SSL write error to client %d\n", clientSocket);
                break;
            }
        }
    }

    // Cleanup
    if (userManager.isLoggedIn(clientSocket)) {
        userManager.logoutUser(clientSocket);
    }
    
    // Get the SSL object from server's map
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        server->sslMap.erase(clientSocket);  // Remove from map
    }
    
    close(clientSocket);
    cout << getColor(clientSocket) << "Client on socket " << clientSocket << " cleaned up and disconnected." << "\033[0m" << endl;

    // After cleanup, notify server about disconnection
    server->decrementClientCount();
}

// 建構函式
ThreadPool::ThreadPool(int numWorkers, Server* serverPtr) : server(serverPtr), isRunning(true) {
    pthread_mutex_init(&queueMutex, nullptr);
    pthread_cond_init(&jobAvailable, nullptr);

    // Create worker threads
    for (int i = 0; i < numWorkers; i++) {
        pthread_t thread;
        if (pthread_create(&thread, nullptr, workerThread, this) == 0) {
            workers.push_back(thread);
        }
    }
    cout << "Thread pool created with " << numWorkers << " worker threads." << endl;
}

// 新增任務
void ThreadPool::addJob(int connectionSocket) {
    pthread_mutex_lock(&queueMutex);
    if (isRunning) {  // Only add jobs if the thread pool is still running
        jobQueue.push(connectionSocket);
        pthread_cond_signal(&jobAvailable);
    } else {
        SSL* ssl = server->sslMap[connectionSocket];
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(connectionSocket);  // If thread pool is shutting down, reject new connections
    }
    pthread_mutex_unlock(&queueMutex);
}

// Shutdown method of the thread pool
void ThreadPool::shutdown() {
    pthread_mutex_lock(&queueMutex);
    isRunning = false;
    pthread_cond_broadcast(&jobAvailable);  // Wake up all waiting threads
    pthread_mutex_unlock(&queueMutex);

    // Wait for all threads to finish
    for (pthread_t worker : workers) {
        pthread_join(worker, nullptr);
    }
    workers.clear();

    // Clear remaining jobs
    while (!jobQueue.empty()) {
        int clientSocket = jobQueue.front();
        jobQueue.pop();
        
        // Get and free SSL object
        SSL* ssl = server->sslMap[clientSocket];
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            server->sslMap.erase(clientSocket);
        }
        close(clientSocket);
    }
}

// 解構函式
ThreadPool::~ThreadPool() {
    shutdown();
    pthread_mutex_destroy(&queueMutex);
    pthread_cond_destroy(&jobAvailable);
    pthread_mutex_destroy(&colorMapMutex);
}

