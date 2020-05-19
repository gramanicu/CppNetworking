#include <iostream>
#include "Networking.hpp"

bool r_in(Networking::Server* sv) {
    std::string command;
    std::cin >> command;
    if (command == "exit") {
        return true;
    }

    return false;
}

bool r_tcp(char* msg, uint sockfd, Networking::Server* sv) {
    std::string message(msg);
    std::cout << msg << " from " << sockfd << "\n";

    sv->send_tcp_message(msg, sockfd);
    return false;
}

bool r_udp(char* msg, sockaddr_in client_addr, Networking::Server* sv) {
    std::cout << inet_ntoa(client_addr.sin_addr) << ":";
    std::cout << ntohs(client_addr.sin_port) << " - ";
    std::cout << std::string(msg) << "\n";

    sv->send_udp_message(msg, client_addr);
    return false;
}

int main() {
    Networking::Server server(8000, &r_in, &r_tcp, &r_udp);
    server.run();
    return 0;
}
