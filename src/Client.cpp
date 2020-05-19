#include <iostream>
#include "Networking.hpp"

bool r_in(Networking::Client* client) {
    std::string command;
    std::cin >> command;
    if (command == "exit") {
        return true;
    }

    if (command.rfind("tcp:", 0) == 0) {
        command.erase(0, 4);
        client->send_tcp_message(command);
    } else if (command.rfind("udp:", 0) == 0) {
        command.erase(0, 4);
        client->send_udp_message(command);
    }

    return false;
}

bool r_tcp(char* msg, uint sockfd) {
    std::string message(msg);
    std::cout << msg << " from " << sockfd << "\n";
    return false;
}

bool r_udp(char* msg, sockaddr_in client_addr) {
    std::cout << inet_ntoa(client_addr.sin_addr) << ":";
    std::cout << ntohs(client_addr.sin_port) << " - ";
    std::cout << std::string(msg) << "\n";
    return false;
}

int main() {
    Networking::Client client("127.0.0.1", 8000, &r_in, &r_tcp, &r_udp);
    client.run();
    return 0;
}