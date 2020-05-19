# Copyright 2020 Grama Nicolae

.PHONY: gitignore clean memory beauty run
.SILENT: beauty clean memory gitignore

# Compilation variables
CC = g++
CFLAGS = -Wno-unused-parameter -Wall -Wextra -pedantic -g -O3 -std=c++17
SRC = $(wildcard */*.cpp)
OBJ = $(SRC:.cpp=.o)

build-all: $(OBJ)

build-server: ./src/Server.o
	$(info Compiling code...)
	@$(CC) -o server $^ $(CFLAGS) ||:
	$(info Compilation successfull)
	-@rm -f *.o ||:

build-client: ./src/Client.o
	$(info Compiling code...)
	@$(CC) -o client $^ $(CFLAGS) ||:
	$(info Compilation successfull)
	-@rm -f *.o ||:

%.o: %.cpp
	$(CC) -o $@ -c $< $(CFLAGS) 

server: clean build-server
	./server

client: clean build-client
	./client

# Deletes the binary and object files
clean:
	rm -f server client $(OBJ)
	echo "Deleted the binary and object files"

# Automatic coding style, in my personal style
beauty:
	clang-format -i -style=file */*.cpp
	clang-format -i -style=file */*.hpp

# Checks the memory for leaks
MFLAGS = --leak-check=full --show-leak-kinds=all --track-origins=yes
memory-server:build-server
	valgrind $(MFLAGS) ./server

memory-client:build-client
	valgrind $(MFLAGS) ./client

# Adds and updates gitignore rules
gitignore:
	@echo "server" > .gitignore ||:
	@echo "client" > .gitignore ||:
	@echo "src/*.o" >> .gitignore ||:
	@echo ".vscode*" >> .gitignore ||:	
	echo "Updated .gitignore"

