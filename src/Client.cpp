#include "Networking.hpp"

bool r_in(Networking::Client* client) {
    return false;
}

bool r_tcp(char* msg, uint sockfd) {
    return false;
}

bool r_udp(char* msg, sockaddr_in client_addr) {
    return false;
}

int main() {
    Networking::Client client("127.0.0.1", 8000, &r_in, &r_tcp, &r_udp);
}