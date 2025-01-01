#include "defAndFuc.hpp"

const string invalidRegister = "Usage: register <username> <password>";
const string invalidLogin = "Usage: login <username> <password>";
const string accountNotAvailable = "Account not available, please try another account.";
const string invalidCommand = "Invalid command, try again.";
const string goodByeMsg = "Goodbye !!";
const string msgToolong = "Message too long.";
const string nameToolong = "Username or password too long !!";
const string targetNameTooLong = "Client's name too long !!";
const string alreadyLogin = "You have already logged in.";
const string userNameExist = "Username already exists.";
const string logoutToRegister = "Please logout first before register new account.";
const string accNotFound = "Account not found, please register first.";
const string incorrectPwd = "Incorrect password, please try again.";
const string logoutMsg = "Logout successfuly !!";
const string notLogin = "You haven't logged in yet.";
const string logoutFirst = "Please logout first before exit.";
const string emptyMsg = "Input something !!";
const string pathTooLong = "File path or name too long !!";

const string registerFailed = "Registration failed.";

const string rejectMsg = "Server is full. Please try again later.";
const string sucMsg = "Welcome to the server!";
const string onlyOneClientOnline = "You are the only client online.";
const string sendCommandInvalid = "Invalid input of send command. Please try again.";
const string invalidSendOption = "Invalid input of send option. Please try again.";
const string invalidSendMsg = "Invalid format of sending input message. Please try again.";

const string invalidInputFormat = "Invalid input format. Please try again.";

const string invalidFileName = "Invalid file name. Please try again.";
const string fileSelectionFailed = "File selection failed and file transfer cancelled!";

// 定義一組顏色代碼
const vector<string> colors = {
    "\033[31m", // 紅色
    "\033[32m", // 綠色
    "\033[33m", // 黃色
    "\033[34m", // 藍色
    "\033[35m", // 紫色
    "\033[36m",  // 青色
};

void printHelp() {
    cout << "\nAvailable commands:" << endl;
    cout << "1. register <username> <password>" << endl;
    cout << "2. login <username> <password>" << endl;
    cout << "3. logout" << endl;
    cout << "4. exit" << endl;
    cout << "5. send" << endl;
    cout << "-----------------------------------------\n";
}

void printMsgSelection(){
    cout << "\nPlease input the number to choose the mode for sending message:\n";
    cout << "1. send message to server\n";
    cout << "2. send message to a specific client（with client's username）\n";
    cout << "3. send file to server\n";
    cout << "4. send file to a client （with client's username）\n";
    cout << "5. send audio to server\n";
    cout << "6. send audio to client（with client's username）\n";
    cout << "-----------------------------------------------------------------\n";
    cout << ">>> ";
}

//! Chat message
void clientSendMsgSelection(){
    cout << "----------------------------------------------------------\n";
    cout << "\nInput format: send <client username> <message>\n";
    cout << "Your input: ";
}
void serverSendMsgSelection(){
    cout << "\nInput format: send <message>\n";
    cout << "Your input: ";
}

//! Audio transfer
void clientSendAudioToServerSelection(){
    cout << "\nInput format: send <audio file path>\n";
    cout << "Your input: ";
}
void clientSendAudioToClientSelection(){
    cout << "----------------------------------------------------------\n";
    cout << "\nInput format: send <client username> <audio file path>\n";
    cout << "Your input: ";
}

//! File transfer
void clientSendFileToServerSelection(){
    cout << "\nInput format: send <filePath>\n";
    cout << "Your input: ";
}
void clientSendFileToClientSelection(){
    cout << "\nInput format: send <client username> <filePath>\n";
    cout << "Your input: ";
}

// Function implementations
void errorCaller(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void toLowerCase(string &str) {
    for (int i = 0; i < str.size(); i++) {
        str[i] = tolower(str[i]);
    }
}

void closeSocket(int socketFD) {
    if (close(socketFD) < 0) {
        errorCaller("Close socket failed");
    }
}

bool isValidIPAddress(char* ip) {
    struct sockaddr_in test_ip_format;
    return inet_pton(AF_INET, ip, &(test_ip_format.sin_addr)) == 1;
}

bool isValidFileName(const string& filename, const string& fileType) {
    //! Check if the file exists
    ifstream file;
    file.open(filename, ios::binary);
    //! Check file type
    bool isValidFileType = true;
    if(fileType != "txt" && fileType != "md" && 
       fileType != "wav"){
        isValidFileType = false;
    }
    regex validFileNameRegex("^[a-zA-Z0-9._-]+$");
    //! Return the checking result
    return regex_match(filename, validFileNameRegex) && 
           filename.find("..") == string::npos && 
           filename.length() <= 255 &&
           file.is_open() && 
           isValidFileType;
}

bool ensureFileDirectory(const string& directory) {
    struct stat st;
    if (stat(directory.c_str(), &st) == 0) {
        // 資料夾已存在
        if (S_ISDIR(st.st_mode)) {
            return true;
        } else {
            cerr << "Error: '" + directory + "' exists but is not a directory.\n";
            return false;
        }
    }

    // 資料夾不存在，嘗試創建
    if (mkdir(directory.c_str(), 0755) != 0) {
        cerr << "Error: Failed to create '" + directory + "' directory: " << strerror(errno) << endl;
        return false;
    }
    return true;
}

string generateFilePath(const string& directory, const string& filename) {
    return directory + "/" + filename;
}

string parseFileType(const string& filePath) {
    // 找到最後一個路徑分隔符
    auto slashPos = filePath.find_last_of("/\\");
    string fileName = (slashPos == string::npos) ? filePath : filePath.substr(slashPos + 1);

    // 找到最後一個點號
    auto dotPos = fileName.find_last_of('.');
    if (dotPos != string::npos) {
        string fileType = fileName.substr(dotPos + 1);
        transform(fileType.begin(), fileType.end(), fileType.begin(), ::tolower); // 轉小寫
        return fileType;
    } else {
        return "";
    }
}