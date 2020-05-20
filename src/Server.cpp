#include "Networking.hpp"

bool conn(uint sockfd, sockaddr_in client_addr, Networking::Server *sv) {
    return false;
}

bool disconn(uint sockfd, Networking::Server *sv) {
    return false;
}

bool r_in(Networking::Server* sv) {
    return false;
}

bool r_tcp(char* msg, uint sockfd, Networking::Server* sv) {
    return false;
}

bool r_udp(char* msg, sockaddr_in client_addr, Networking::Server* sv) {
    return false;
}

int main() {
    Networking::Server sv(8000, &r_in, &r_tcp, &r_udp, &conn, &disconn);
}