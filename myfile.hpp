#ifndef MY_FILE_HPP
#define MY_FILE_HPP

#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iomanip>  // 包含 setw 和 setfill

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
// #include <openssl/sha.h>  // 引入 OpenSSL 的 SHA-256 支援

using namespace std;

#define CHUNK_SIZE 1024 // 1 KB

#define FRAME_SIZE 8192 // 8 KB

#define MAX_FILE_SIZE 1024 * 1024 * 100 // 100 MB

namespace FileProcessing{

class FileReader {
    public:
        //! Default implementation for every function
        virtual ~FileReader() = default;
        virtual bool openSendFile(const string& filePath) { throw runtime_error("Not yet implemented"); }
        virtual bool openReceiveFile(const string& filePath) { throw runtime_error("Not yet implemented"); }
        virtual void process_send(SSL* ssl_conn) { }
        virtual void process_receive_server(SSL* ssl_conn) { }
        virtual void receiveAndSendFile(SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username) { }
        virtual void storeFileContentForClient(vector<vector<string>>& fileBuffer) { }
        virtual void calculateFileHash(uint8_t status) { }
        virtual string getHash(uint8_t status) { return "";}
        virtual void close() { }

        //! Add new function for audio handling
        virtual void closeAudio() { }
};

class TextFileReader : public FileReader {
    private:
        ifstream file;
        ofstream receiveFile;
        string fileHash;
        string fileHashReceived;
    public:
        // Calculate the file hash.
        void calculateFileHash(uint8_t status) override;
        string getHash(uint8_t status) override;
        //! For file transfer within client-server
        // filePath Path to the file.
        bool openSendFile(const string& filePath) override; 
        bool openReceiveFile(const string& filePath) override;

        // This function defines how the file content will be handled for sending. 
        void process_send(SSL* ssl_conn) override;
        // This function defines how the file content will be handled for receiving.
        void process_receive_server(SSL* ssl_conn) override;
        
        //! For file transfer within client-client
        // This function defines how the file will be handled for receiving and sending by server.
        void receiveAndSendFile(SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username) override;

        // Store the file content for client.
        void storeFileContentForClient(vector<vector<string>>& fileBuffer) override;

        // Closes the file.
        void close() override;
};

// Add new class for audio handling
class AudioFileReader : public FileReader {
    private:
        ifstream audioFileSend;
        char audioToStream[FRAME_SIZE];

    public:
        bool openSendFile(const string& filePath) override;
        void process_send(SSL* ssl_conn) override;
        void process_receive_server(SSL* ssl_conn) override;
        void receiveAndSendFile(SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username) override;
        void closeAudio() override;
};

// A unique_ptr to a FileReader instance. To insure the memory operation.
unique_ptr<FileReader> createFileReader(const string& fileType);

} // namespace FileProcessing

const string FILE_HEADER = "FILE:"; // 設定固定的標頭
const string AUDIO_HEADER = "AUDIO:"; // 設定固定的標頭

bool sendFile(const string& filePath, unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn);
bool receiveFileServer(const string& filePath, unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn);
bool reTransferFile(unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username);

bool sendAudioFile(const string& filePath, unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn);
bool receiveAndPlayAudioFileServer(unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_conn);
bool reTransferAudioFile(unique_ptr<FileProcessing::FileReader>& fileReader, SSL* ssl_giver, SSL* ssl_target, const string& filename, const string& username);
#endif