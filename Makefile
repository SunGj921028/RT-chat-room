CXX = g++
CXXFLAGS = -g -lm -pthread -lssl -lcrypto

SRCS_SERVER = ./server.cpp ./ThreadPool.cpp ./UserManager.cpp ./defAndFuc.cpp ./myfile.cpp
SRCS_CLIENT = ./client.cpp ./defAndFuc.cpp ./myfile.cpp

OBJ_SERVER = $(SRCS_SERVER:.cpp=.o)
OBJ_CLIENT = $(SRCS_CLIENT:.cpp=.o)

# 預設目標: 同時編譯 server 和 client
all: server client

# 編譯 server 執行檔
server: $(OBJ_SERVER)
	$(CXX) $(OBJ_SERVER) -o $@ $(CXXFLAGS)

# 編譯 client 執行檔
client: $(OBJ_CLIENT)
	$(CXX) $(OBJ_CLIENT) -o $@ $(CXXFLAGS)

# 編譯 .cpp 檔案為 .o 檔案，並生成依賴檔案
%.o: %.cpp
	$(CXX) -MMD -MP -c $< -o $@ $(CXXFLAGS)

# 引入依賴檔案
-include $(OBJ_SERVER:.o=.d) $(OBJ_CLIENT:.o=.d)

# 清理生成的檔案
clean:
	rm -f $(OBJ_SERVER) $(OBJ_CLIENT) $(OBJ_SERVER:.o=.d) $(OBJ_CLIENT:.o=.d) server client
