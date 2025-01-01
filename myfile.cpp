#include "myfile.hpp"

//? Text file reader
// Open the file for sending
bool FileProcessing::TextFileReader::openSendFile(const string& filePath) {
    file.open(filePath, ios::binary | ios::in);
    if (!file.is_open()) {
        throw runtime_error("Failed to open text file: " + filePath + ". File may not exist or be inaccessible.");
        return false;
    }else{ return true;}
}

// Open the file for receiving
bool FileProcessing::TextFileReader::openReceiveFile(const string& filePath) {
    receiveFile.open(filePath, ios::binary | ios::out);
    if (!receiveFile.is_open()) {
        throw runtime_error("Failed to open text file: " + filePath + ". File may not exist or be inaccessible.");
        return false;
    }else{ return true;}
}

//! Client send file to server
void FileProcessing::TextFileReader::process_send(SSL* ssl_conn) {
    char buffer[CHUNK_SIZE] = {0};
    int countChunk = 0;
    cout << "-----------------------------------------------------------------\n";
    while (1) {
        memset(buffer, 0, CHUNK_SIZE);
        file.read(buffer, CHUNK_SIZE);
        streamsize bytesRead = file.gcount(); // 實際讀取的字節數
        if (bytesRead <= 0) { break; }

        const char* bufferPtr = buffer;
        cout << "Sending " << ++countChunk << " chunk of " << bytesRead << " bytes\n";
        while(bytesRead > 0){
            ssize_t bytesSent = SSL_write(ssl_conn, bufferPtr, bytesRead);
            if (bytesSent <= 0) {
                int ssl_error = SSL_get_error(ssl_conn, bytesSent);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue; // 暫時無法讀取，繼續重試
                }else if(ssl_error == SSL_ERROR_SYSCALL){
                    throw runtime_error("SSL_write failed due to system error: " + string(strerror(errno)));
                }else if(ssl_error == SSL_ERROR_SSL){
                    throw runtime_error("SSL_write failed due to SSL protocol error.");
                }else{
                    throw runtime_error("SSL_write encountered unknown error.");
                }
            }
            bytesRead -= bytesSent;
            bufferPtr += bytesSent;
        }
    }
    SSL_write(ssl_conn, "EOF", 3);
    cout << "-----------------------------------------------------------------\n";
}

//! Server receive file from client
void FileProcessing::TextFileReader::process_receive_server(SSL* ssl_conn) {
    ssize_t totalBytesReceived = 0;
    char buffer[CHUNK_SIZE] = {0};
    int countChunk = 0;
    cout << "-----------------------------------------------------------------\n";
    cout << "Receiving File...\n";
    while (1) {
        memset(buffer, 0, CHUNK_SIZE);
        ssize_t bytesRead = SSL_read(ssl_conn, buffer, CHUNK_SIZE);
        if (bytesRead <= 0) {
            int ssl_error = SSL_get_error(ssl_conn, bytesRead);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // 暫時無法讀取，繼續重試
            }else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Clean shutdown
                //? Means receive file successfully and end
                break;
            }else if(ssl_error == SSL_ERROR_SYSCALL){
                throw runtime_error("SSL_read failed due to system error: " + string(strerror(errno)));
            }else if(ssl_error == SSL_ERROR_SSL){
                throw runtime_error("SSL_read failed due to SSL protocol error.");
            }else{
                throw runtime_error("SSL_read encountered unknown error.");
            }
        }
        //! EOF 
        if(string(buffer, bytesRead).find("EOF") != string::npos){
            break;
        }
        totalBytesReceived += bytesRead;
        if(totalBytesReceived > MAX_FILE_SIZE){
            throw runtime_error("File size exceeds the maximum limit of " + to_string(MAX_FILE_SIZE) + " bytes.");
        }
        // Write the received data to file
        receiveFile.write(buffer, bytesRead);
        if (!receiveFile) {
            throw runtime_error("Failed to write to file");
        }
        cout << "Received " << ++countChunk << " chunk of file with " << bytesRead << " bytes\n";
    }
    cout << "\nFile reception complete.\n";
    cout << "-----------------------------------------------------------------\n";
}

//! Server re-send file to specific client
void FileProcessing::TextFileReader::receiveAndSendFile(SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username) {
    ssize_t totalBytesReceived = 0;
    char buffer[CHUNK_SIZE] = {0};
    int countChunk = 0;
    cout << "\n-----------------------------------------------------------------\n";
    cout << "Receiving for re-sending to specific client...\n";
    vector<vector<char>> chunks;

    // 初始化 SHA-256 context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw runtime_error("Failed to create EVP_MD_CTX.");
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to initialize SHA-256.");
    }

    while (1) {
        memset(buffer, 0, CHUNK_SIZE);
        ssize_t bytesRead = SSL_read(ssl_giver, buffer, CHUNK_SIZE);
        if (bytesRead <= 0) {
            int ssl_error = SSL_get_error(ssl_giver, bytesRead);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // 暫時無法讀取，繼續重試
            }else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Clean shutdown
                //? Means receive file successfully and connection end
                break;
            }else if(ssl_error == SSL_ERROR_SYSCALL){
                throw runtime_error("SSL_read failed due to system error: " + string(strerror(errno)));
            }else if(ssl_error == SSL_ERROR_SSL){
                throw runtime_error("SSL_read failed due to SSL protocol error.");
            }else{
                throw runtime_error("SSL_read encountered unknown error.");
            }
        }
        //! EOF 
        if(string(buffer, bytesRead).find("EOF") != string::npos){
            break;
        }

        // 同時計算 hash 和儲存數據
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Failed to update SHA-256 hash.");
        }

        // 將讀取到的資料加入暫時緩衝
        chunks.emplace_back(buffer, buffer + bytesRead);
        totalBytesReceived += bytesRead;
        if(totalBytesReceived > MAX_FILE_SIZE){
            memset(buffer, 0, CHUNK_SIZE);
            chunks.clear();
            EVP_MD_CTX_free(mdctx); //! Free the SHA-256 context
            throw runtime_error("File size exceeds the maximum limit of " + to_string(MAX_FILE_SIZE) + " bytes.");
        }
    }
    cout << "Receive complete. File total size: " << totalBytesReceived << " bytes\n";

    // 完成 hash 計算
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to finalize SHA-256 hash.");
    }
    EVP_MD_CTX_free(mdctx);

    // 將 hash 轉換為十六進制字串
    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    string hashValueOfRetransmitFile = oss.str();
    cout << "Hash value of the re-sent file is: " << hashValueOfRetransmitFile << endl << endl;

    string chunkHeader = "INFO:" + to_string(totalBytesReceived) + " bytes | " + filename + " | " + hashValueOfRetransmitFile + " | " + username;
    if(SSL_write(ssl_target, chunkHeader.c_str(), chunkHeader.length()) <= 0){
        throw runtime_error("Failed to send chunk header to target client.");
    }

    // Send file content
    for (const auto& chunk : chunks) {
        // 构建带有前缀的缓冲区
        vector<char> prefixedChunk(FILE_HEADER.begin(), FILE_HEADER.end());
        prefixedChunk.insert(prefixedChunk.end(), chunk.begin(), chunk.end());
        ssize_t bytesSent = SSL_write(ssl_target, prefixedChunk.data(), prefixedChunk.size());

        if (bytesSent <= 0) {
            int ssl_error = SSL_get_error(ssl_target, bytesSent);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue;
            } else {
                throw runtime_error("SSL_write failed: unexpected error.");
            }
        }

        cout << "Sent chunk of size: " << bytesSent - FILE_HEADER.size() << " bytes\n";
    }
    // Send EOF to target client
    SSL_write(ssl_target, "EOF", 3);
    cout << "\nFile reception and re-sending complete.\n";
    cout << "-----------------------------------------------------------------\n";
}

//! Store file data when client receives file
void FileProcessing::TextFileReader::storeFileContentForClient(vector<vector<string>>& fileBuffer) {
    //! Write the file content to the file
    for (const auto& chunk : fileBuffer) {
        for (const auto& str : chunk) {
            // Write the string content to the file
            receiveFile.write(str.c_str(), str.length());
            if (!receiveFile) {
                throw runtime_error("Failed to write chunk to file");
            }
            cout << "Received chunk of size: " << str.length() << " bytes\n";
        }
    }
    receiveFile.flush();  // Ensure all data is written to disk
}

void FileProcessing::TextFileReader::close() {
    if (file.is_open()) {
        file.close();
    }
    if (receiveFile.is_open()) {
        receiveFile.close();
    }
}

//! Calculate the hash of the file
void FileProcessing::TextFileReader::calculateFileHash(uint8_t status) {
    //! Calculate the hash of the file being sent
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw runtime_error("Failed to create EVP_MD_CTX.");
    }
    // 初始化 SHA-256
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to initialize SHA-256.");
    }
    char buffer[1024];
    file.seekg(0);  // 回到檔案開頭
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Failed to update SHA-256 hash.");
        }
    }
    // 處理剩餘的字節
    if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to update SHA-256 hash.");
    }

    // 完成哈希計算
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to finalize SHA-256 hash.");
    }

    EVP_MD_CTX_free(mdctx);

    // 將哈希值轉換為十六進制字串
    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    if(status == 0){
        //! Store the hash of the file being sent
        fileHash = oss.str();
    }else if(status == 1){
        //! Store the hash of the file being received
        fileHashReceived = oss.str();
    }
    
}

//! Get the hash of the file（send or receive）
string FileProcessing::TextFileReader::getHash(uint8_t status) {
    if(status == 0){ return fileHash;}
    else { return fileHashReceived;}
}

//! Get the file type, and create the corresponding file reader
unique_ptr<FileProcessing::FileReader> FileProcessing::createFileReader(const string& fileType) {
    if (fileType == "txt" || fileType == "md") {
        return make_unique<FileProcessing::TextFileReader>();
    } else if (fileType == "wav") {
        return make_unique<FileProcessing::AudioFileReader>();
    }
    // 支援未來更多檔案類型
    throw runtime_error("Unsupported file type: " + fileType);
}


//! Send file from client
bool sendFile(const string& filePath, unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn){
    try {
        //! Calculate the hash of the file
        if(!fileReader->openSendFile(filePath)){ throw runtime_error("Failed to open file for sending.");}
        fileReader->calculateFileHash(0);
        fileReader->close();
        //! Send the file
        if(!fileReader->openSendFile(filePath)){ throw runtime_error("Failed to open file for sending.");}
        fileReader->process_send(ssl_conn);
        fileReader->close();
        return true;
    } catch (const exception& e) {
        cerr << "Error during file sending: " << e.what() << endl;
        return false;
    }
}

//! Server receive file from client without re-sending
bool receiveFileServer(const string& filePath, unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn){
    try {
        if(!fileReader->openReceiveFile(filePath)){ throw runtime_error("Failed to open file for receiving.");}
        fileReader->process_receive_server(ssl_conn);
        fileReader->close();
        return true;
    }catch (const exception& e) {
        cerr << "Error during file receiving: " << e.what() << endl;
        return false;
    }
}

//! Server receive file from client and re-send to specific client
bool reTransferFile(unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username){
    try {
        fileReader->receiveAndSendFile(ssl_giver, ssl_target, filename, username);
        return true;
    }catch (const exception& e) {
        cerr << "Error during file re-sending: " << e.what() << endl;
        return false;
    }
}


//? Audio file reader
bool FileProcessing::AudioFileReader::openSendFile(const string& filePath) {
    audioFileSend.open(filePath, ios::binary | ios::in);
    if (!audioFileSend.is_open()) {
        throw runtime_error("Failed to open audio file: " + filePath + ". File may not exist or be inaccessible.");
        return false;
    }else{ return true;}
}

void FileProcessing::AudioFileReader::process_send(SSL *ssl_conn) {
    // Open file already done in openSendFile
    char audioBuffer[FRAME_SIZE] = {0};
    int countFrame = 0;
    cout << "-----------------------------------------------------------------\n";
    while(!audioFileSend.eof()){
        memset(audioBuffer, 0, FRAME_SIZE);
        audioFileSend.read(audioBuffer, FRAME_SIZE);
        streamsize bytesRead = audioFileSend.gcount();
        if(bytesRead <= 0){ break; }

        const char* bufferPtr = audioBuffer;
        cout << "Sending " << ++countFrame << " frame of " << bytesRead << " bytes\n";
        while(bytesRead > 0){
            ssize_t bytesSent = SSL_write(ssl_conn, bufferPtr, bytesRead);
            if (bytesSent <= 0) {
                int ssl_error = SSL_get_error(ssl_conn, bytesSent);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    continue; // 暫時無法讀取，繼續重試
                }else if(ssl_error == SSL_ERROR_SYSCALL){
                    throw runtime_error("SSL_write failed due to system error: " + string(strerror(errno)));
                }else if(ssl_error == SSL_ERROR_SSL){
                    throw runtime_error("SSL_write failed due to SSL protocol error.");
                }else{
                    throw runtime_error("SSL_write encountered unknown error.");
                }
            }
            bytesRead -= bytesSent;
            bufferPtr += bytesSent;
        }
    }
    SSL_write(ssl_conn, "EOF", 3);
    cout << "-----------------------------------------------------------------\n";
    return;
}

void FileProcessing::AudioFileReader::closeAudio() {
    if (audioFileSend.is_open()) {
        audioFileSend.close();
    }else{ throw runtime_error("Failed to close audio file.");}
}

void FileProcessing::AudioFileReader::process_receive_server(SSL * ssl_conn){
    ssize_t totalBytesReceived = 0;
    char audioBuffer[FRAME_SIZE] = {0};
    int countFrame = 0;
    FILE* audioPipe = popen("aplay -", "w");
    if(!audioPipe){
        throw runtime_error("Failed to open audio pipe for playback.");
    }
    cout << "-----------------------------------------------------------------\n";
    cout << "Receiving Audio...\n";
    while(1){
        ssize_t bytesRead = SSL_read(ssl_conn, audioBuffer, FRAME_SIZE);
        if (bytesRead <= 0) {
            int ssl_error = SSL_get_error(ssl_conn, bytesRead);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // 暫時無法讀取，繼續重試
            }else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Clean shutdown
                //? Means receive file successfully and end
                break;
            }else if(ssl_error == SSL_ERROR_SYSCALL){
                throw runtime_error("SSL_read failed due to system error: " + string(strerror(errno)));
            }else if(ssl_error == SSL_ERROR_SSL){
                throw runtime_error("SSL_read failed due to SSL protocol error.");
            }else{
                throw runtime_error("SSL_read encountered unknown error.");
            }
        }

        if(string(audioBuffer, bytesRead).find("EOF") != string::npos){
            break;
        }

        totalBytesReceived += bytesRead;
        if(totalBytesReceived > MAX_FILE_SIZE){
            throw runtime_error("File size exceeds the maximum limit of " + to_string(MAX_FILE_SIZE) + " bytes.");
        }

        // Write the received data to file
        fwrite(audioBuffer, sizeof(char), bytesRead, audioPipe);
        cout << "Received " << ++countFrame << " frame of file with " << bytesRead << " bytes\n";
    }

    pclose(audioPipe);
    cout << "\nAudio reception and playback complete. Total has " << totalBytesReceived << " bytes received\n";
    cout << "-----------------------------------------------------------------\n";
    return;
}

void FileProcessing::AudioFileReader::receiveAndSendFile(SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username){
    ssize_t totalBytesReceived = 0;
    char audioBuffer[FRAME_SIZE] = {0};
    int countFrame = 0;
    vector<char> audioFileBuffer;
    cout << "\n-----------------------------------------------------------------\n";
    cout << "Receiving audio file for re-sending to specific client...\n";

    while (1) {
        memset(audioBuffer, 0, FRAME_SIZE);
        ssize_t bytesRead = SSL_read(ssl_giver, audioBuffer, FRAME_SIZE);
        if (bytesRead <= 0) {
            int ssl_error = SSL_get_error(ssl_giver, bytesRead);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                continue; // 暫時無法讀取，繼續重試
            }else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                // Clean shutdown
                //? Means receive file successfully and connection end
                break;
            }else if(ssl_error == SSL_ERROR_SYSCALL){
                throw runtime_error("SSL_read failed due to system error: " + string(strerror(errno)));
            }else if(ssl_error == SSL_ERROR_SSL){
                throw runtime_error("SSL_read failed due to SSL protocol error.");
            }else{
                throw runtime_error("SSL_read encountered unknown error.");
            }
        }
        //! EOF
        if(string(audioBuffer, bytesRead).find("EOF") != string::npos){
            break;
        }

        // 將讀取到的資料加入暫時緩衝
        audioFileBuffer.insert(audioFileBuffer.end(), audioBuffer, audioBuffer + bytesRead);
        totalBytesReceived += bytesRead;
        if(totalBytesReceived > MAX_FILE_SIZE){
            memset(audioBuffer, 0, FRAME_SIZE);
            audioFileBuffer.clear();
            throw runtime_error("File size exceeds the maximum limit of " + to_string(MAX_FILE_SIZE) + " bytes.");
        }
    }
    cout << "Audio file receive complete. File total size: " << totalBytesReceived << " bytes\n";

    // Write the header of the audio file
    string audioHeader = "AUDIOINFO:" + to_string(totalBytesReceived) + " bytes | " + filename + " | " + username;
    if(SSL_write(ssl_target, audioHeader.c_str(), audioHeader.length()) <= 0){
        throw runtime_error("Failed to send chunk header to target client.");
    }

    // Re-send the audio file content
    size_t offset = 0;
    while(offset < audioFileBuffer.size()){
        size_t frameSize = 0;
        if (audioFileBuffer.size() - offset < FRAME_SIZE) {
            frameSize = audioFileBuffer.size() - offset;
        } else {
            frameSize = FRAME_SIZE;
        }
        vector<char> frame(audioFileBuffer.begin() + offset, audioFileBuffer.begin() + offset + frameSize);
        ssize_t bytesSent = SSL_write(ssl_target, frame.data(), frame.size());
        if (bytesSent <= 0) {
            int ssl_error = SSL_get_error(ssl_target, bytesSent);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                throw runtime_error("SSL_write failed: unexpected error.");
            }
        }
        offset += frameSize;
        cout << "Sent frame of size: " << bytesSent << " bytes\n";
    }
    // Send EOF to target client
    SSL_write(ssl_target, "EOF", 3);
    cout << "\nAudio file re-sent complete. With total audio file size " << totalBytesReceived << " bytes\n";
    cout << "-----------------------------------------------------------------\n";
    return;
}

bool sendAudioFile(const string& filePath, unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn){
    try {
        if(!fileReader->openSendFile(filePath)){
            throw runtime_error("Failed to open audio file: " + filePath);
        }
        fileReader->process_send(ssl_conn);
        cout << "\nAudio file sent successfully!!!\n";
        fileReader->closeAudio();
        return true;
    } catch (const exception& e) {
        cerr << "Error during audio sending: " << e.what() << endl;
        return false;
    }
}

bool receiveAndPlayAudioFileServer(unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn){
    try {
        cout << "Receiving audio file and start streaming...\n";
        fileReader->process_receive_server(ssl_conn);
        return true;
    }catch (const exception& e) {
        cerr << "Error during file receiving: " << e.what() << endl;
        return false;
    }
}

bool reTransferAudioFile(unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username){
    try {
        fileReader->receiveAndSendFile(ssl_giver, ssl_target, filename, username);
        return true;
    }catch (const exception& e) {
        cerr << "Error during file re-sending: " << e.what() << endl;
        return false;
    }
}

