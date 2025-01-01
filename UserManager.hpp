#ifndef USER_MANAGER_HPP
#define USER_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <pthread.h>

using namespace std;

class User {
    private:
        string username;
        string password;
        bool isLoggedIn;

    public:
        User(const string& username, const string& password);
        const string& getUsername() const;
        const string& getPassword() const;
        bool checkPassword(const string& password) const;
        bool getLoginStatus() const;
        void setLoginStatus(bool status);
};

class UserManager {
private:
    vector<User> users;                      // 所有用戶
    map<int, string> clientStatus;           // 客戶端狀態 (socket 對應的 username，已登入狀態)
    mutable pthread_mutex_t mutex;           // POSIX 互斥鎖
    const string userFile = "users.txt";

    void loadUsers();

public:
    UserManager();
    ~UserManager();
    void saveUsers(string& username, string& password);
    bool registerUser(const string& username, const string& password);
    bool loginUser(int clientSocket, const string& username, const string& password);
    void logoutUser(int clientSocket);
    bool isLoggedIn(int clientSocket) const;
    bool isAccountAvailable(const string& username) const;
    bool isAccountExist(const string& username) const;
    string getClientUsername(int clientSocket) const;

    string printLoginUserList(int clientSocket) const;
    int getClientSocketNumFromStatus(const string& username) const;
    int countOnlineClients() const;
};

extern UserManager userManager;

#endif
