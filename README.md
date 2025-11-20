### Project Description
- **real-time online chatroom** application with **secure communication**
  - allows users to communicate through various media types, including text message, files, and audio streaming.

### Project DEMO video (建議調整撥放速度為 0.75 倍觀看)
- https://www.youtube.com/watch?v=BcTFOp-aB6Y

---

### 環境設定
- 請務必在 **Linux** 系統使用
  - 需要安裝 `alsa-utils`
    - `sudo apt-get install alsa-utils`
- 需要支援以下主要的標頭檔
  - `#include <netinet/in.h>`
  - `#include <arpa/inet.h>`
  - `#include <sys/socket.h>`
  - `#include <openssl/ssl.h>`
  - `#include <openssl/err.h>`
  - `#include <openssl/evp.h>`
  - `#include <pthread.h>`
  - `#include <fstream>`
  - `#include <sstream>`
  - `#include <netdb.h>`

---

### How to use
1. 執行 `make` 編譯出 `client` 以及 `server` 可執行檔
2. 使用以下方式執行兩個可執行檔（server 需先執行）
    - `./server <port_number>`
    - `./client <IP_address> <port_number>`
      - （IP address, port number 需要對到要連接的 server）
3. 依照印出的選項執行其他功能操作

![image](https://github.com/SunGj921028/RT-chat-room/blob/main/img/example.png)

---

### Example
- `./server 8080`
- `./client 127.0.0.1 8080`
  - IP address 需合法
  - IP_address, port_number 請輸入數字

---

### 檔案簡易說明
```cpp
RT-chat-room/
├── client.cpp      // client 端的功能實作
├── server.cpp      // server 端的功能實作
├── server.hpp      // server 的 class，儲存與定義 server 相關內容
├── ThreadPool.cpp  // multiThread 與 worker pool design 功能實作
├── ThreadPool.hpp  // ThreadPool的class，儲存與定義 thread,pool 相關內容
├── UserManager.cpp // 使用者相關功能實作
├── UserManager.hpp // 使用者 class 儲存與定義 user 相關內容
├── myfile.cpp      // 檔案相關的功能實作
├── myfile.hpp      // Audio, file 的 class 以及 檔案處理的 namespace
├── defAndFuc.cpp   // 通用 function 實作，變數放置處
└── defAndFuc.hpp   // 通用 function 與變數定義
```
- 傳輸檔案的過程中會有一些資料夾被產生以儲存傳輸的檔案

---

### 功能實作
- **Basic Server-Client Communication**
  - client 跟 server 之間的**訊息傳遞**
    - client 可以傳遞訊息給 server 並接收 server 的回覆
    - server 可以接收 client 的訊息，並回覆訊息給 client
- **Authentication Features**
  - client 端的使用者可以執行以下的操作
    - **註冊**使用者帳號（設定帳號以及密碼）
    - **登入**使用者帳號
    - **登出**使用者帳號（有設計要先登出可以輸入 `exit` 結束程式） 
- **Multithread server**
  - 讓 server 可以同時處理最多 **MAX_CLIENT** 的 client 連線數量（預設為最多 **10 個** clients，若超過會顯示 server 不能再接收新的連線請求）
    - 使用 **POSIX threads（pthread）** 以及 **worker pool design pattern** 來實作
- **Sending Chat Messages**
  - 實作設計是 **Relay Mode（client 跟 client 間透過 server 來溝通）**
  - client 可以**透過 server** 來當作溝同橋梁獲取要互動的 client 的 IP address 以及 port number，以實現 client 跟 client 之間的**訊息傳遞**
- **Message Encryption with OpenSSL**
  - 為 client-client 和 client-server 建立一個 **secure communication system**
  - 透過 `#include <openssl/ssl.h>` 提供的 SSL 庫進行實作
- **Transfer files**
  - 擴展溝通系統，新增檔案傳輸的功能，支援 client-server 以及 client-client
  - 檔案將透過切分 chunks 的方式傳送
  - 傳送內容同樣透過 SSL 進行加密解密
  - 傳輸的檔案需放在與程式同層級的資料夾 RT-chat-room/ 裡
- **Audio Streaming**
  - **frame-based streaming feature for audio**
  - 傳送內容同樣透過 SSL 進行加密解密
  - 透過 `alsa-utils` 撥放音訊（使用 `aplay`）
  - 傳輸的檔案需放在與程式同層級的資料夾 RT-chat-room/ 裡
- **GUI Interface**
  - 將不同 client 所傳遞的內容都印上了不同的代表顏色，方便分辨哪些內容是哪些 client 傳遞的
  - server 給 client 的回覆也統一印上了黃色

---

### 程式執行流程
#### server
1. 接收指定的 port number
2. 用 **`socket()`** 建立 server 的 file descriptor
3. 將 fd **`bind()`** 到 IP address 跟 port
4. 開始 **`listen()`** 連接，設定最大可連接數量（10）
5. 設定 **SSL Context**，以及處理 multithread 的 **pool**（最多 10 個 worker），建立**多執行緒**來處理
6. 使用 **`accept()`** 開始 handle connections
7. 以 connection 的 fd 建立 SSL 連線通道
8. 將 connection 的 fd 放入 pool 的 JobQueue 中
9. 持續接收 client（worker），並同時處理 job 中的已連線 client 的內容

#### client
1. 用 `socket()` 建立 client socket file descriptor
2. 從接收的 arguments，用 `connect()` 連線到 server
3. 設定 **SSL context**，並建立 SSL connection
4. 每一個 client 有自己用來持續接收 server 傳遞內容的 thread 防止阻塞
5. 使用實際功能

---


