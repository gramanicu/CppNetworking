/**
 * Copyright (c) 2020 Grama Nicolae
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file Networking.hpp
 * @author Grama Nicolae (gramanicu@gmail.com)
 * @brief This is a simple library that manages tcp/udp connections. It defines
 * both a server and a client
 * @version 1.0
 * @date 19-05-2020
 *
 * @copyright Copyright (c) 2020
 *
 */

#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <set>
#include <sstream>
#include <string>

#define lint uint64_t  // Long Int
#define uint uint32_t  // Unsigned Int
#define sint uint16_t  // Short Int
#define bint uint8_t   // Byte Int
#define uchar unsigned char

#define FOREVER while (1)
#define MAX_CLIENTS UINT32_MAX
#define BUFFER_SIZE 1500
#define ENABLE_LOGS true

/**
 * @brief Check if the condition is met. If it doesn't, print message and exit
 */
#define MUST(condition, message) \
    if (!(condition)) {          \
        std::cerr << message;    \
        exit(-1);                \
    }

/**
 * @brief Check if the error happens. If it does, print it
 */
#define CERR(condition)                                   \
    if (condition) {                                      \
        std::cerr << __FILE__ << ", " << __LINE__ << ": " \
                  << std::strerror(errno) << "\n";        \
    }

/**
 * @brief This function is similar to strncpy
 * Because strcpy is vulnerable to buffer overflows and strncpy doesn't
 * necessarily end strings with null terminator, this is solved using this
 * function. Works like strlcpy
 */
void safe_cpy(char *dst, const char *src, size_t size) {
    *((char *)mempcpy(dst, src, size)) = '\0';
}

/**
 * @brief Print messages to STDOUT
 * Will only print if ENABLE_LOGS is true
 * @param msg The message to be printed
 */
void console_log(const std::string &msg) {
    if (ENABLE_LOGS) {
        std::cout << msg;
    }
}

namespace Networking {
/**
 * @brief Clear the file descriptors
 */
void clear_fds(fd_set *read_fds, fd_set *tmp_fds) {
    FD_ZERO(read_fds);
    FD_ZERO(tmp_fds);
}

/**
 * @brief Close a socket
 * @param sockfd The socket to be closed
 */
void close_skt(int sockfd) {
    CERR(shutdown(sockfd, SHUT_RDWR) != 0);
    CERR(close(sockfd) != 0);
}

/**
 * @brief A tcp/udp server. For each type of message (udp, tcp, stdin),
 * a function must be assigned.
 */
class Server {
   private:
    uint main_port, main_tcp_sock, udp_sock, max_fd;
    bool (*read_input)(Server *);
    bool (*read_tcp)(char *, uint, Server *);
    bool (*read_udp)(char *, sockaddr_in, Server *);
    bool (*new_connection)(uint, sockaddr_in, Server *);
    bool (*disconnect)(uint, Server *);
    fd_set read_fds, tmp_fds;
    sockaddr_in listen_addr;

    std::set<uint> client_sockets;

    /**
     * @brief Prepare, bind and start listening
     */
    void init_connections() {
        MUST(bind(main_tcp_sock, (sockaddr *)&listen_addr, sizeof(sockaddr)) >=
                 0,
             "Could not bind tcp socket\n");
        MUST(listen(main_tcp_sock, MAX_CLIENTS) >= 0,
             "Could not start listening for tcp connections\n");
        MUST(bind(udp_sock, (sockaddr *)&listen_addr, sizeof(sockaddr)) >= 0,
             "Could not bind udp socket\n");

        // Set the file descriptors for the sockets
        FD_SET(main_tcp_sock, &read_fds);
        FD_SET(udp_sock, &read_fds);
        max_fd = std::max(main_tcp_sock, udp_sock);

        // Set the file descriptor for STDIN
        FD_SET(STDIN_FILENO, &read_fds);
    }

    /**
     * @brief This function manages new TCP connections
     */
    bool accept_connection() {
        // Accept the new connection
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_sockfd =
            accept(main_tcp_sock, (sockaddr *)&client_addr, &client_len);
        CERR(new_sockfd < 0);

        // Add the new socket
        FD_SET(new_sockfd, &read_fds);
        max_fd = std::max(max_fd, (uint)new_sockfd);

        client_sockets.insert(new_sockfd);

        return new_connection(new_sockfd, client_addr, this);
    }

    /**
     * @brief This function manages tcp messages
     * @param sockfd The socket on which the message will be read
     */
    bool read_tcp_message(uint sockfd) {
        char msg[BUFFER_SIZE];
        bzero(&msg, BUFFER_SIZE);

        ssize_t msg_size = recv(sockfd, &msg, sizeof(msg), 0);
        CERR(msg_size < 0);

        if (msg_size == 0) {
            // Client disconnected
            close_skt(sockfd);
            FD_CLR(sockfd, &read_fds);
            client_sockets.erase(sockfd);

            return disconnect(sockfd, this);
        } else {
            return read_tcp(msg, sockfd, this);
        }
    }

    /**
     * @brief This function manages udp messages
     */
    bool read_udp_message() {
        char msg[BUFFER_SIZE];
        bzero(&msg, BUFFER_SIZE);

        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t msg_size = recvfrom(udp_sock, &msg, sizeof(msg), 0,
                                    (sockaddr *)&client_addr, &client_len);
        CERR(msg_size < 0);

        return read_udp(msg, client_addr, this);
    }

   public:
    /**
     * @brief Send a udp message to the specified address
     * @param client_addr The address
     * @param text The text in the message
     */
    void send_udp_message(sockaddr_in client_addr, std::string text) {
        char msg[BUFFER_SIZE];
        safe_cpy(msg, text.c_str(), text.size());
        CERR(sendto(udp_sock, msg, strlen(msg) + 1, 0, (sockaddr *)&client_addr,
                    sizeof(client_addr)) < 0);
    }

    /**
     * @brief Send a udp message to the specified address
     * @param client_addr The adress
     * @param msg The buffer
     */
    void send_udp_message(sockaddr_in client_addr, char *msg) {
        CERR(sendto(udp_sock, msg, strlen(msg) + 1, 0, (sockaddr *)&client_addr,
                    sizeof(client_addr)) < 0);
    }

    /**
     * @brief Send tcp message on the specified socket
     * @param tcp_sock The socket number
     * @param text The text in the message
     */
    void send_tcp_message(uint tcp_sock, std::string text) {
        char msg[BUFFER_SIZE];
        safe_cpy(msg, text.c_str(), text.size());
        CERR(send(tcp_sock, msg, strlen(msg) + 1, 0) < 0);
    }

    /**
     * @brief Send tcp message on the specified socket
     * @param tcp_sock The socket number
     * @param msg The buffer
     */
    void send_tcp_message(uint tcp_sock, char *msg) {
        CERR(send(tcp_sock, msg, strlen(msg) + 1, 0) < 0);
    }

    /**
     * @brief Send a tcp message to all the clients
     * @param msg The buffer
     */
    void broadcast_tcp_message(char *msg) {
        for (auto &sockfd : client_sockets) {
            CERR(send(sockfd, msg, strlen(msg) + 1, 0) < 0);
        }
    }

    /**
     * @brief Send a tcp message to all the clients
     * @param text The text in the message
     */
    void broadcast_tcp_message(std::string text) {
        char msg[BUFFER_SIZE];
        safe_cpy(msg, text.c_str(), text.size());
        for (auto &sockfd : client_sockets) {
            CERR(send(sockfd, msg, strlen(msg) + 1, 0) < 0);
        }
    }

    /**
     * @brief Return a set with all client's sockets
     * @return std::set<uint>& The set of sockets
     */
    std::set<uint> &get_clients_sockfd() { return client_sockets; }

    /**
     * @brief Construct a new server
     * @param main_port The port of the server
     * @param fin A function that manages stdin "events"
     * @param ftcp A function that manages new tcp messages
     * @param fudp A function that manages new udp messages
     * @param new_conn A function that manages new connection (aditional
     * functionality)
     * @param disconn A function that manages disconnects (aditional
     * functionality) All the 5 function return a bool, that tells the server
     * whether or not to close
     */
    explicit Server(const uint main_port, bool (*fin)(Server *),
                    bool (*ftcp)(char *, uint, Server *),
                    bool (*fudp)(char *, sockaddr_in, Server *),
                    bool (*new_conn)(uint, sockaddr_in, Server *),
                    bool (*disconn)(uint, Server *))
        : main_port(main_port),
          max_fd(0),
          read_input(fin),
          read_tcp(ftcp),
          read_udp(fudp),
          new_connection(new_conn),
          disconnect(disconn) {
        // Initialise the main TCP socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        CERR(sock < 0);
        MUST(sock >= 0, "Couldn't create main TCP socket\n");

        main_tcp_sock = sock;

        // Initialise the UDP socket
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        CERR(sock < 0);
        MUST(sock >= 0, "Couldn't create UDP socket\n");
        udp_sock = sock;

        // Clear the file descriptors sets
        clear_fds(&read_fds, &tmp_fds);

        // Set the socket options
        const int opt = 1;

        // Next two options are used to be able to restart the server on the
        // same port without waiting for TCP_WAIT to expire
        CERR(setsockopt(main_tcp_sock, SOL_SOCKET, SO_REUSEADDR,
                        (const char *)&opt, sizeof(opt)) != 0);

#ifdef SO_REUSEPORT
        CERR(setsockopt(main_tcp_sock, SOL_SOCKET, SO_REUSEPORT,
                        (const char *)&opt, sizeof(opt)) != 0);
#endif

        // Set the listen adress
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(main_port);
        listen_addr.sin_addr.s_addr = INADDR_ANY;
    }

    /**
     * @brief Destroy the Server object
     */
    ~Server() {
        // Close connections
        close_skt(main_tcp_sock);

        for (auto &sock : client_sockets) {
            close_skt(sock);
        }
    }

    /**
     * @brief Run the server
     */
    void run() {
        init_connections();
        do {
            tmp_fds = read_fds;
            CERR(select(max_fd + 1, &tmp_fds, NULL, NULL, NULL) < 0);
            for (uint i = 0; i <= max_fd; ++i) {
                if (FD_ISSET(i, &tmp_fds)) {
                    if (i == STDIN_FILENO) {
                        if (read_input(this)) {
                            return;
                        }
                    } else if (i == main_tcp_sock) {
                        if (accept_connection()) {
                            return;
                        }
                    } else if (i == udp_sock) {
                        if (read_udp_message()) {
                            return;
                        }
                    } else if (i != STDOUT_FILENO && i != STDERR_FILENO) {
                        if (read_tcp_message(i)) {
                            return;
                        }
                    }
                }
            }
        }
        FOREVER;
    }
};

class Client {
   private:
    uint tcp_sock, udp_sock, server_port, max_fd;
    fd_set read_fds, tmp_fds;
    sockaddr_in server_addr;
    bool (*read_input)(Client *);
    bool (*read_tcp)(char *, uint);
    bool (*read_udp)(char *, sockaddr_in);

#pragma GCC push_options  // Disable optimisations for this function
#pragma GCC optimize("-O0")
    /**
     * @brief Connect to server
     */
    void init_connection() {
        // Connect to the server
        MUST(connect(tcp_sock, (sockaddr *)&server_addr, sizeof(server_addr)) ==
                 0,
             "Couldn't connect to the server\n");

        // Set the file descriptors for the sockets
        FD_SET(tcp_sock, &read_fds);
        FD_SET(udp_sock, &read_fds);
        max_fd = std::max(tcp_sock, udp_sock);

        // Set the file descriptor for STDIN
        FD_SET(STDIN_FILENO, &read_fds);
    }
#pragma GCC pop_options

    /**
     * @brief This function manages tcp messages
     */
    bool read_tcp_message() {
        char msg[BUFFER_SIZE];
        bzero(&msg, BUFFER_SIZE);

        ssize_t msg_size = recv(tcp_sock, &msg, sizeof(msg), 0);
        CERR(msg_size < 0);

        if (msg_size == 0) {
            // Serverc closed = Close client
            FD_CLR(tcp_sock, &read_fds);
            return true;
        } else {
            return read_tcp(msg, tcp_sock);
        }
    }

    /**
     * @brief This function manages udp messages
     */
    bool read_udp_message() {
        char msg[BUFFER_SIZE];
        bzero(&msg, BUFFER_SIZE);

        sockaddr_in server_addr;
        socklen_t server_len = sizeof(server_addr);
        ssize_t msg_size = recvfrom(udp_sock, &msg, sizeof(msg), 0,
                                    (sockaddr *)&server_addr, &server_len);
        CERR(msg_size < 0);

        return read_udp(msg, server_addr);
    }

   public:
    /**
     * @brief Send an udp message
     * @param msg The buffer
     */
    void send_udp_message(char *msg) {
        CERR(sendto(udp_sock, msg, strlen(msg) + 1, 0, (sockaddr *)&server_addr,
                    sizeof(server_addr)) < 0);
    }

    /**
     * @brief Send an udp message
     * @param msg The text in the message
     */
    void send_udp_message(std::string text) {
        char msg[1500];
        safe_cpy(msg, text.c_str(), text.size());
        CERR(sendto(udp_sock, msg, strlen(msg) + 1, 0, (sockaddr *)&server_addr,
                    sizeof(server_addr)) < 0);
    }

    /**
     * @brief Send tcp message to the server
     * @param msg The buffer
     */
    void send_tcp_message(char *msg) {
        CERR(send(tcp_sock, msg, strlen(msg) + 1, 0) < 0);
    }

    /**
     * @brief Send tcp message to the server
     * @param text The text in the message
     */
    void send_tcp_message(std::string text) {
        char msg[1500];
        safe_cpy(msg, text.c_str(), text.size());
        CERR(send(tcp_sock, msg, strlen(msg) + 1, 0) < 0);
    }

    /**
     * @brief Construct a new Client
     * @param ip The ip of the server
     * @param port The port of the server (tcp)
     * @param fin A function that manages stdin "events"
     * @param ftcp A function that manages new tcp messages
     * @param fudp A function that manages new udp messages
     * All the 3 function return a bool, that tells the client whether or not to
     * close
     */
    Client(const char *ip, const uint port, bool (*fin)(Client *),
           bool (*ftcp)(char *, uint), bool (*fudp)(char *, sockaddr_in))
        : server_port(port),
          max_fd(0),
          read_input(fin),
          read_tcp(ftcp),
          read_udp(fudp) {
        // Initialise the TCP socket
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        MUST(sock >= 0, "Failed to initialise socket\n");
        tcp_sock = sock;

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        CERR(sock < 0);
        MUST(sock >= 0, "Couldn't create UDP socket\n");
        udp_sock = sock;

        // Clear the file descriptors sets
        clear_fds(&read_fds, &tmp_fds);

        // Set the server adress
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        MUST(inet_aton(ip, &server_addr.sin_addr) != 0, "Invalid IP adress\n");
    }

    ~Client() {
        // Close connection
        close_skt(tcp_sock);
    }

    void run() {
        init_connection();
        do {
            tmp_fds = read_fds;

            // The maximum fd is the socket fd
            CERR(select(max_fd + 1, &tmp_fds, NULL, NULL, NULL) < 0);
            for (uint i = 0; i <= max_fd; ++i) {
                if (FD_ISSET(i, &tmp_fds)) {
                    if (i == STDIN_FILENO) {
                        if (read_input(this)) {
                            // Close the client
                            return;
                        }
                    } else if (i == tcp_sock) {
                        if (read_tcp_message()) {
                            // Close the client
                            return;
                        }
                    } else if (i == udp_sock) {
                        if (read_udp_message()) {
                            // Close the client
                            return;
                        }
                    }
                }
            }
        }
        FOREVER;
    }
};

}  // namespace Networking
