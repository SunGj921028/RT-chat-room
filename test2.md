## NTNU 41147005S 傅靖嘉 - Final Project README

### Personal Project Description
- **real-time online chatroom** application with **secure communication**
  - allows users to communicate through various media types, including text, files, and live video streaming.

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
1. 進入 code/ 資料夾，並執行 `make` 編譯出 `client` 以及 `server` 可執行檔
2. 使用以下方式執行兩個可執行檔（server 需先執行）
    - `./server <port_number>`
    - `./client <IP_address> <port_number>`
      - （IP address, port number 需要對到要連接的 server）
3. 依照印出的選項執行其他功能操作
![螢幕擷取畫面 2024-12-25 164456](https://hackmd.io/_uploads/rkFUuSFByx.png)


---

### 使用範例（demo 影片使用）
- `./server 8080`
- `./client 127.0.0.1 8080`
  - IP address 需合法
  - IP_address, port_number 請輸入數字

---

### 檔案簡易說明
```cpp
code/
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


---

### 已經完成的功能實作（後面會有實際的實作說明）
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
- **Audio Streaming**
  - **frame-based streaming feature for audio**
  - 傳送內容同樣透過 SSL 進行加密解密
  - 透過 `alsa-utils` 撥放音訊（使用 `aplay`）
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

### 功能實作完整說明
#### Basic Server-Client Communication
- client 的使用者都需要在**登入**的情況才下可以使用 send 內的功能
- 支援 client 直接傳訊息給 server
- 支援 client 透過 username 去選擇**上線狀態**的 client 來指定要傳遞訊息的 client

---

#### Authentication Features
- 提供了以下一組預設的使用者供使用
  - username：**tmp**
  - password：**tmp**
- 支援讓 client 端的使用者輸入 username, password 去註冊新的帳號，這個新帳號的資訊在程式結束後會被保存下來供下次登入時使用
  - 要依照 `register <username> <password>` 的格式輸入
    - username 以及 password 最長皆為 50 個字元，輸入不能為空
    - username 不能重複
- 支援讓 client 端的使用者輸入 username, password 登入已經存在的帳號
  - 登入須按照輸入格式輸入 `login <username> <password>`
    - username 以及 password 最長皆為 50 個字元，輸入不能為空
  - 不能登入已經是登入狀態的帳號
  - 不能登入不存在的帳號
  - 已經登入的時候要先登出
- 支援讓 client 端的使用者輸入 `logout` 登出帳號
  - 需要在登入狀態下才有用
  - 輸入只能包含 `logout`
- 支援讓使用者輸入 `exit` 結束與 server 的連線與程式本身

---

#### Multithread server
- **讓 server 可以透過多執行緒同時處理多個 client 的連線**
- 最大的同時可連線數量設定為 **MAX_CLIENT（10）**
- 使用 **`pthread`** 以及 **`worker pool design`**
  - server 啟動後，會建立一個大的 thread pool，並初始化 threadPool 的 class
  - 使用 **`pthread_create()`** 建立多個執行緒並將這些執行緒存進 worker 的 陣列中，以實現多執行緒並行
  - 每個 thread 會去看目前有沒有 Job 在 queue 裡，如果沒有就用 **`pthread_cond_wait()`** 等待
  - 每和一個 client 建立一個新連線，這個連線的 fd 會存進 JobQueue 裡面
- 使用 **`pthread_mutex_lock()`** 和 **`pthread_mutex_unlock()`** 防止多個執行緒同時操作同一個變數
- client 端每一個 client 會有自己接收 server 資訊的 thread，會不斷的嘗試接收 server 那端的訊息或其他傳遞的內容，以避免有阻塞的情況發生，每個 thread 都用 **`pthread_detach()`** 分離。

---

#### Sending Chat Messages
- 支援 **client-server** 以及 **client-client**
  - client 如果要傳送訊息給另一個 client，傳遞與被傳遞的 client 都必須在線上，且之間的傳遞會透過 server 來溝通 **（Relay Mode）**
- 當選擇要傳給 client，會先列出已上線的 client 的 username，client 可以透過在已上線的 client 中選擇想要傳遞訊息的 client 的 username 來告知 server 想要傳遞的對象以及訊息的內容
- client 會一直監聽有沒有訊息傳送過來，並且會知道是 client 送過來的還是 server
- 傳輸有進行加密與解密

---

#### Message Encryption with OpenSSL
- 標頭檔
  - `#include <openssl/ssl.h>`
  - `#include <openssl/err.h>`
- 支援 client-server 與 client-client 之間的訊息、檔案和音訊檔傳輸的加密與解密
- 使用 `SSL_library_init()`、`SSL_load_error_strings()`、`OpenSSL_add_all_algorithms()`、`SL_CTX_new(TLS_server_method())` 以及 `SSL_CTX_new(TLS_client_method())` 來初始化 **SSL context**
- server 需要使用 `SSL_CTX_use_certificate_file()` 以及 `SSL_CTX_use_PrivateKey_file` 來設定 certificate 跟 private key files，再使用 `SSL_new()` 建立通道並透過`SSL_accept()` 來接收 client 的連線
- client 會在初始化時，使用 `SSL_CTX_load_verify_locations()` 載入來自 server 的可信任的憑證，再透過 `SSL_CTX_set_verify()` 設定證書驗證，再使用 `SSL_CTX_set_cipher_list()` 設定安全的加密套件，最後透過 `SSL_CTX_set_options()` 禁止舊版協議
  - 初始化後透過 `SSL_new()`、 `SSL_set_fd()` 以及 `SSL_connect()` 建立與 server 間的 SSL 連線通道
- 傳遞都使用 `SSL_write()` 以及 `SSL_read()`，這是 SSL 內建的函式，經過這兩個傳送與接收的內容會被自動的加密與解密

---

#### Transfer files
- 需要登入才可以使用
- 檔案皆切分為**每個 CHUNK 1KB（1024）**
- 檔案傳送和接收會計算 hash value 確認檔案是否完整傳輸
- 分為兩種
  - client-server
    - server 單純接收檔案並存在 serverFile/ 的資料集裡，檔案名稱會加上時間戳以避免檔案名稱重複
  - client-client
    - 會先查看有沒有一個以上的 client 是**登入狀態**，有的話會列出已上線的 client 的 username 供 client 選擇
    - 檔案會儲存在 clientFile_targetUserName/ 資料夾裡，檔案名稱會加上時間戳以避免檔案名稱重複
- 傳輸有進行加密與解密


---
