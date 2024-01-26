#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <map>
#include <functional>
#include <fstream>
#include <sstream>
#include <csignal>
#include <chrono>

struct Account {
    std::string username;
    std::string password;
    std::vector<std::string> friends;
    std::vector<int> rooms;
    int clientSocket = -1; 
};

struct Message {
    std::string username;
    std::string text;
};

struct Room {
    int number;
    std::vector<std::string> users;
    std::vector<Message> messages;

    Room(int number, const std::vector<std::string>& users, const std::vector<Message>& messages)
        : number(number), users(users), messages(messages) {}
};

std::vector<Account> accounts;
std::vector<Room> rooms;

void loadAccounts() {
    std::ifstream file("accounts.txt");
    std::string username, password;

    while (file >> username >> password) {
        accounts.push_back({username, password});
    }
}

void loadFriendsAndRooms() {
    std::ifstream file("friends.txt");
    std::string line;

    while (std::getline(file, line)) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(line);
        while (std::getline(tokenStream, token, ':')) {
            tokens.push_back(token);
        }

        if (tokens.size() != 3) {
            continue;
        }

        std::string user1 = tokens[0];
        std::string user2 = tokens[1];
        std::string roomNumber = tokens[2];

        auto user1It = std::find_if(accounts.begin(), accounts.end(), [&](const Account& user) {
            return user.username == user1;
        });

        auto user2It = std::find_if(accounts.begin(), accounts.end(), [&](const Account& user) {
            return user.username == user2;
        });

        if (user1It != accounts.end() && user2It != accounts.end()) {
            user1It->friends.push_back(user2);
            user2It->friends.push_back(user1);
        }

        rooms.push_back({std::stoi(roomNumber), {user1, user2}, {}});
    }
}

void loadRoomsMessages() {
    for (Room& room : rooms) {
        std::ifstream messageFile("room" + std::to_string(room.number) + ".txt");
        std::string line;
        while (std::getline(messageFile, line)) {
            std::string username = line;
            std::getline(messageFile, line);  
            Message message;
            message.username = username;
            message.text = line;
            room.messages.push_back(message);
        }
    }
}

void handleLogin(int clientSocket,  std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string loginPrefix = "LOGIN_";
    if (message.substr(0, loginPrefix.size()) == loginPrefix) {
        size_t underscorePos = message.find('_', loginPrefix.size());
        if (underscorePos != std::string::npos) {
            std::string username = message.substr(loginPrefix.size(), underscorePos - loginPrefix.size());
            std::string password = message.substr(underscorePos + 1);

            auto it = std::find_if(accounts.begin(), accounts.end(), [&](const Account& account) {
                return account.username == username && account.password == password;
            });

            if (it != accounts.end()) {
                it->clientSocket = clientSocket;
                std::string successMessage = "LOGIN_SUCCESS_" + username;
                send(clientSocket, successMessage.c_str(), successMessage.size(), 0);
            } else {
                std::string failureMessage = "LOGIN_FAIL";
                send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
            }
        }
    }
}

void handleRegister(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string registerPrefix = "REGISTER_";
    if (message.substr(0, registerPrefix.size()) == registerPrefix) {
        size_t underscorePos = message.find('_', registerPrefix.size());
        if (underscorePos != std::string::npos) {
            std::string username = message.substr(registerPrefix.size(), underscorePos - registerPrefix.size());
            std::string password = message.substr(underscorePos + 1);

            auto it = std::find_if(accounts.begin(), accounts.end(), [&](const Account& account) {
                return account.username == username;
            });

            if (it == accounts.end()) {
                accounts.push_back({username, password});

                std::ofstream accountsFile("accounts.txt", std::ios::app);
                if (accountsFile.is_open()) {
                    accountsFile << username << " " << password << "\n";
                    accountsFile.close();
                }

                std::string successMessage = "Registration successful\n";
                send(clientSocket, successMessage.c_str(), successMessage.size(), 0);
            } else {
                std::string failureMessage = "Username already exists\n";
                send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
            }
        }
    }
}

void handleLeaveRoom(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string leavePrefix = "LEAVE_";
    if (message.substr(0, leavePrefix.size()) == leavePrefix) {
        std::string rest = message.substr(leavePrefix.size());
        int roomNumber = std::stoi(rest.substr(0, rest.find('_')));
        std::string username = rest.substr(rest.find('_') + 1);

        auto userIt = std::find_if(accounts.begin(), accounts.end(), [&](const Account& user) {
            return user.username == username;
        });

        if (userIt != accounts.end()) {
            auto roomIt = std::find(userIt->rooms.begin(), userIt->rooms.end(), roomNumber);

            if (roomIt != userIt->rooms.end()) {
                userIt->rooms.erase(roomIt);
                std::string successMessage = message + "\n";

                for (const Account& user : accounts) {
                    if (std::find(user.rooms.begin(), user.rooms.end(), roomNumber) != user.rooms.end()) {
                        if (user.clientSocket != clientSocket) {
                            send(user.clientSocket, successMessage.c_str(), successMessage.size(), 0);
                        }
                    }
                }
            } else {
                std::string failureMessage = "You are not in this room\n";
                send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
            }
        } else {
            std::string failureMessage = "User does not exist\n";
            send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
        }
    }
}

void handleAddFriend(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string addPrefix = "ADD_";
    if (message.substr(0, addPrefix.size()) == addPrefix) {
        std::string rest = message.substr(addPrefix.size());
        std::string username1 = rest.substr(0, rest.find('_'));
        std::string username2 = rest.substr(rest.find('_') + 1);

        auto user1It = std::find_if(accounts.begin(), accounts.end(), [&](const Account& user) {
            return user.username == username1;
        });

        auto user2It = std::find_if(accounts.begin(), accounts.end(), [&](const Account& user) {
            return user.username == username2;
        });

        if (user1It != accounts.end() && user2It != accounts.end()) {
            user1It->friends.push_back(username2);
            user2It->friends.push_back(username1);

            int roomNumber;
            do {
                roomNumber = rand() % 10000; // Generate a random room number between 0 and 9999
            } while (std::find_if(rooms.begin(), rooms.end(), [&](const Room& room) {
                return room.number == roomNumber;
            }) != rooms.end());

            rooms.push_back({roomNumber, {username1, username2}, {}});  // Change this line
            user1It->rooms.push_back(roomNumber);
            user2It->rooms.push_back(roomNumber);
            std::cout << "Created room with number: " << roomNumber << std::endl;

            std::ofstream file("friends.txt", std::ios::app);  // Open the file in append mode
            if (file.is_open()) {
                file << username1 << ":" << username2 << ":" << roomNumber << "\n";
                file.close();
            } else {
                std::cerr << "Unable to open file";
            }

            std::string user1Message = "FRIENDS_" + username2;
            std::string user2Message = "FRIENDS_" + username1;

            send(user1It->clientSocket, user1Message.c_str(), user1Message.size(), 0);
            send(user2It->clientSocket, user2Message.c_str(), user2Message.size(), 0);
        }
    }
}

void handleRoomMessages(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string prefix = "ROOMMESSAGES_";
    if (message.substr(0, prefix.size()) == prefix) {
        int roomNumber = std::stoi(message.substr(prefix.size()));

        auto roomIt = std::find_if(rooms.begin(), rooms.end(), [&](const Room& room) {
            return room.number == roomNumber;
        });

        if (roomIt != rooms.end()) {
            for (const Message& message : roomIt->messages) {
                std::string roomMessage = "MESSAGE_" + std::to_string(roomNumber) + "_" + message.username + ":" + message.text + "\n";
                send(clientSocket, roomMessage.c_str(), roomMessage.size(), 0);
            }
        } else {
            std::string failureMessage = "Failed to get room messages\n";
            send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
        }
    }
}

void handleEnterRoom(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string prefix = "ENTER_";
    if (message.substr(0, prefix.size()) == prefix) {
        int roomNumber = std::stoi(message.substr(prefix.size(), message.find("_", prefix.size()) - prefix.size()));
        std::string username = message.substr(message.find("_", prefix.size()) + 1);

        auto roomIt = std::find_if(rooms.begin(), rooms.end(), [&](const Room& room) {
            return room.number == roomNumber;
        });

        if (roomIt != rooms.end()) {
            std::string enterMessage = "ENTER_" + std::to_string(roomNumber) + "_" + username + "\n";

            for (auto& account : accounts) {
                if (account.username == username) {
                    account.rooms.push_back(roomNumber);
                }
                if (std::find(account.rooms.begin(), account.rooms.end(), roomNumber) != account.rooms.end()) {
                    if (account.clientSocket != -1 && account.clientSocket != clientSocket) {
                        send(account.clientSocket, enterMessage.c_str(), enterMessage.size(), 0);
                    }
                }
            }
        } else {
            std::string failureMessage = "Failed to send enter message\n";
            send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
        }
    }
}

void handleRoomNumber(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string prefix = "ROOMNUMBER_";
    if (message.substr(0, prefix.size()) == prefix) {
        std::string currentUser = message.substr(prefix.size(), message.find("_", prefix.size()) - prefix.size());
        std::string friendUsername = message.substr(message.find("_", prefix.size()) + 1);

        auto roomIt = std::find_if(rooms.begin(), rooms.end(), [&](const Room& room) {
            return std::find(room.users.begin(), room.users.end(), currentUser) != room.users.end() &&
                   std::find(room.users.begin(), room.users.end(), friendUsername) != room.users.end();
        });

        if (roomIt != rooms.end()) {
            std::string roomNumberMessage = "ROOMNUMBER_" + std::to_string(roomIt->number);
            for (const auto& username : roomIt->users) {
                roomNumberMessage += "_" + username;
            }
            send(clientSocket, roomNumberMessage.c_str(), roomNumberMessage.size(), 0);
        } else {
            std::string failureMessage = "Failed to get room number\n";
            send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
        }
    }
}

void handleSendMessage(int clientSocket, std::string message) {
    if (!message.empty() && message.back() == '\n') {
        message.pop_back();
    }
    std::string prefix = "SEND_";
    if (message.substr(0, prefix.size()) == prefix) {
        std::string username = message.substr(prefix.size(), message.find("_", prefix.size()) - prefix.size());
        int roomNumber = std::stoi(message.substr(message.find("_", prefix.size()) + 1, message.find("_", message.find("_", prefix.size()) + 1) - message.find("_", prefix.size()) - 1));
        std::string text = message.substr(message.find("_", message.find("_", prefix.size()) + 1) + 1);

        auto roomIt = std::find_if(rooms.begin(), rooms.end(), [&](const Room& room) {
            return room.number == roomNumber;
        });

        if (roomIt != rooms.end()) {
            roomIt->messages.push_back({username, text});

            std::ofstream file("room" + std::to_string(roomNumber) + ".txt", std::ios::app);
            file << username << '\n' << text << '\n';
            std::string roomMessage = "MESSAGE_" + std::to_string(roomNumber) + "_" + username + ":" + text;

            for (const auto& account : accounts) {
                if (std::find(account.rooms.begin(), account.rooms.end(), roomNumber) != account.rooms.end()) {
                    if (account.clientSocket != -1) {
                        send(account.clientSocket, roomMessage.c_str(), roomMessage.size(), 0);
                    }
                }
            }
        } else {
            std::string failureMessage = "Failed to send message\n";
            send(clientSocket, failureMessage.c_str(), failureMessage.size(), 0);
        }
    }
}

void handleFriendsRequest(int clientSocket, std::string message) {
    std::string username = message.substr(8); 

    auto it = std::find_if(accounts.begin(), accounts.end(), [&](const Account& account) {
        return account.username == username;
    });

    if (it != accounts.end()) {
        std::string friends = "FRIENDS_";
        for (const std::string& friendUsername : it->friends) {
            if (friends.size() > 8) {
                friends += ",";
            }
            friends += friendUsername;
        }

        send(clientSocket, friends.c_str(), friends.size(), 0);
    }
}

void handleExit(int clientSocket, const std::string& message) {
    std::string exitMessage = "EXIT";
    send(clientSocket, exitMessage.c_str(), exitMessage.size(), 0);
}

std::map<std::string, std::function<void(int, std::string)>> handlers = {
    {"LOGIN", handleLogin},
    {"REGISTER", handleRegister},
    {"LEAVE", handleLeaveRoom},
    {"ADD", handleAddFriend},
    {"SEND", handleSendMessage},
    {"FRIENDS", handleFriendsRequest},
    {"ROOMMESSAGES", handleRoomMessages},
    {"ROOMNUMBER", handleRoomNumber},
    {"ENTER", handleEnterRoom},
    {"EXIT", handleExit}, 
};

std::vector<int> clientSockets;
std::vector<std::thread> threads; 
int serverSocket;

void handleClient(int clientSocket, int threadIndex) {
    char buffer[1024] = {0};

    while (true) {
        ssize_t bytesRead = read(clientSocket, buffer, 1024);
        if (bytesRead <= 0) {
            break;
        }

        std::string message(buffer, bytesRead);
        std::cout<<"Message from client: "<<message<<std::endl;
        

        std::string prefix = message.substr(0, message.find('_'));
        auto it = handlers.find(prefix);
        if (it != handlers.end()) {
            it->second(clientSocket, message);
        } else {
            std::string errorMessage = "Invalid command\n";
            send(clientSocket, errorMessage.c_str(), errorMessage.size(), 0);
        }
        if (message == "EXIT") {
            break; 
        }
    }
    std::cout << "Closing client thread..." << std::endl;
    clientSockets.erase(std::remove(clientSockets.begin(), clientSockets.end(), clientSocket), clientSockets.end());
    threads.erase(threads.begin() + threadIndex);
    close(clientSocket);
}


void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum << ") received.\n";

    std::string exitMessage = "EXIT";
    for (int clientSocket : clientSockets) {
        send(clientSocket, exitMessage.c_str(), exitMessage.size(), 0);
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (std::thread& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    close(serverSocket);

    std::cout << "Closing server ..." << std::endl;
    exit(signum);
}

int main() {
    std::cout << "Starting server..." << std::endl;

    std::cout << "Creating socket..." << std::endl;
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    std::cout << "Binding socket..." << std::endl;
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(12345);

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }

    std::cout << "Listening for connections..." << std::endl;
    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Failed to listen for connections" << std::endl;
        return 1;
    }

    signal(SIGINT, signalHandler);
    std::cout << "Loading accounts, friends, rooms, and messages..." << std::endl;
    loadAccounts();
    loadFriendsAndRooms();
    loadRoomsMessages();
    std::cout << "Server is ready to accept connections." << std::endl;
    while (true) {
        sockaddr_in clientAddress{};
        socklen_t clientAddressLength = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (clientSocket == -1) {
            std::cerr << "Failed to accept connection" << std::endl;
            continue;
        }

        clientSockets.push_back(clientSocket);
        std::cout << "Accepted a connection. Handling client's request in a new thread..." << std::endl;

        int threadIndex = threads.size();
        std::thread clientThread([clientSocket, threadIndex]() {
            handleClient(clientSocket, threadIndex);
            close(clientSocket); 
        });
        clientThread.detach();
        threads.push_back(std::move(clientThread));
    }
    std::cout << "Closing server ..." << std::endl;
    close(serverSocket);

    return 0;
}
