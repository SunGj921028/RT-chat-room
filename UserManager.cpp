#include "UserManager.hpp"
#include "server.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>

// User class constructor
User::User(const string& username, const string& password) 
    : username(username), password(password), isLoggedIn(false) 
{}

// Get the username
const string& User::getUsername() const {
    return username;
}

// Get the password
const string& User::getPassword() const {
    return password;
}

// Check if the password is correct for login
bool User::checkPassword(const string& password) const {
    return this->password == password;
}

// Get the login status for the user
bool User::getLoginStatus() const {
    return isLoggedIn;
}

// Set the login status for the user
void User::setLoginStatus(bool status) {
    isLoggedIn = status;
}

// UserManager class variable
UserManager userManager;

// UserManager class constructor
UserManager::UserManager() {
    pthread_mutex_init(&mutex, nullptr);
    clientStatus.clear();
    loadUsers(); //? Load the user data from the file users.txt
}

// UserManager class destructor
UserManager::~UserManager() {
    clientStatus.clear();
    pthread_mutex_destroy(&mutex);
}

// Load the user data from the file users.txt
void UserManager::loadUsers() {
    ifstream file(userFile);
    if (!file.is_open()) return;

    string username, password;
    while (file >> username >> password) {
        users.emplace_back(username, password);
    }
    file.close();
}

// Save the user data to the file users.txt
void UserManager::saveUsers(string& username, string& password) {
    ofstream file(userFile, ios::app);
    if (!file.is_open()) return;
    file << username << " " << password << "\n";
    file.close();
}

// Register a new user
bool UserManager::registerUser(const string& username, const string& password) {
    pthread_mutex_lock(&mutex);
    for (const auto& user : users) {
        if (user.getUsername() == username) { //? Account already exists
            pthread_mutex_unlock(&mutex);
            return false;
        }
    }
    users.emplace_back(username, password);
    pthread_mutex_unlock(&mutex);
    return true;
}

// Login a user
bool UserManager::loginUser(int clientSocket, const string& username, const string& password) {
    pthread_mutex_lock(&mutex);
    for (auto& user : users) {
        if (user.getUsername() == username) { //? Check if the account exists
            if (user.getLoginStatus() || !user.checkPassword(password)) {
                pthread_mutex_unlock(&mutex);
                return false;
            }
            user.setLoginStatus(true); //? Set the login status to true
            clientStatus[clientSocket] = username; //? Add the client to the login map
            pthread_mutex_unlock(&mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&mutex);
    return false;
}

// Logout a user
void UserManager::logoutUser(int clientSocket) {
    pthread_mutex_lock(&mutex);
    auto it = clientStatus.find(clientSocket);
    if (it != clientStatus.end()) {
        for (auto& user : users) {
            if (user.getUsername() == it->second) { //? Find the user to logout
                user.setLoginStatus(false);
                break;
            }
        }
        clientStatus.erase(it); //? Remove the client from the login map
    }
    pthread_mutex_unlock(&mutex);
}

// Check if the client has logged in
bool UserManager::isLoggedIn(int clientSocket) const {
    pthread_mutex_lock(&mutex);
    bool loggedIn = clientStatus.find(clientSocket) != clientStatus.end();
    pthread_mutex_unlock(&mutex);
    return loggedIn;
}

// Check if the account whether can be logged in
bool UserManager::isAccountAvailable(const string& username) const {
    pthread_mutex_lock(&mutex);
    for (const auto& user : users) {
        if (user.getUsername() == username && !user.getLoginStatus()) { //? Check if the account exists and is not logged in by other client
            pthread_mutex_unlock(&mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&mutex);
    return false;
}

// Check if the account exists
bool UserManager::isAccountExist(const string& username) const {
    pthread_mutex_lock(&mutex);
    for (const auto& user : users) {
        if (user.getUsername() == username) {
            pthread_mutex_unlock(&mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&mutex);
    return false;
}

string UserManager::getClientUsername(int clientSocket) const { //! Get the matching account name from logged-in accounts
    pthread_mutex_lock(&mutex);
    auto it = clientStatus.find(clientSocket);
    string username = (it != clientStatus.end()) ? it->second : "";
    pthread_mutex_unlock(&mutex);
    return username;
}

// Print the list of logged-in accounts
string UserManager::printLoginUserList(int clientSocket) const {
    pthread_mutex_lock(&mutex);
    ostringstream oss;
    if (clientStatus.empty()) {
        oss << "No clients are currently logged in." << endl;
    } else {
        oss << "\nBelow is the list of clients who are online except yourself:\n";  
        for (const auto& user : clientStatus) {
            if(user.first != clientSocket){ //? Exclude the client who called this function
                struct sockaddr_in clientInfo; // Auto delete
                socklen_t addrlen = sizeof(clientInfo);
                if(getpeername(user.first, (struct sockaddr*)&clientInfo, &addrlen) == 0){
                    oss << "    " << "( client socket: " << user.first << " , username: " << user.second << " , IP: " << inet_ntoa(clientInfo.sin_addr) << " , Port: " << ntohs(clientInfo.sin_port) << " )" << endl;
                }
            }
        }
    }
    // oss << "\n----------------------------------------------------------\n";
    pthread_mutex_unlock(&mutex);
    return oss.str();
}

// Count the number of client online
int UserManager::countOnlineClients() const {
    pthread_mutex_lock(&mutex);
    int count = clientStatus.size();
    pthread_mutex_unlock(&mutex);
    return count;
}

// Get the client socket number from the login map
int UserManager::getClientSocketNumFromStatus(const string& username) const {
    pthread_mutex_lock(&mutex);
    for (const auto& user : clientStatus) {
        if (user.second == username) {
            pthread_mutex_unlock(&mutex);
            return user.first;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}
