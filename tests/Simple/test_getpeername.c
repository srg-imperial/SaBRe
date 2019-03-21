/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{timeout} 2 %{vx} %t1 &> %t1.actual
 * RUN: echo "Success" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <assert.h>

#define PORT 55555
#define ADDR "127.0.0.1"

/*
 * This test forks a server and connects to it.
 * Then, it uses the connection to test getpeername on both ends.
 * Socket pair sv[2] is used to make the client connect only when the server is ready.
 * This test fails if:
 *  - getpeername doesn't fill in the second argument with the correct address;
 *  - The leader and the follower get a peer name.
*/

static void test_getpeername(int socket, struct sockaddr_in * addr, int addr_size) {
  char ipstr[INET_ADDRSTRLEN];
  struct sockaddr_in *s;
  int port;

  getpeername(socket, (struct sockaddr*)addr, &addr_size);
  s    = (struct sockaddr_in *)addr;
  port = ntohs(s->sin_port);
  inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);

  assert(!strncmp(ipstr, ADDR, sizeof(ADDR)));
  assert(port == PORT);

  ipstr[INET_ADDRSTRLEN-1] = '\0';
  open(ipstr, O_RDONLY);
}

int main(){
  char buffer[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
    printf("Failed to create Unix-domain socket pair\n");
    return -1;
  }

  pid_t pid;
  if (pid = fork()) {
    // Parent / Client

    close(sv[1]);
    read(sv[0], buffer, sizeof(buffer));

    int clientSocket;

    /*---- Create the socket. The three arguments are: ----*/
    /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);

    /*---- Configure settings of the server address struct ----*/
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(PORT);
    /* Set IP address to localhost */
    serverAddr.sin_addr.s_addr = inet_addr(ADDR);
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    /*---- Connect the socket to the server using the address struct ----*/
    addr_size = sizeof serverAddr;
    if (connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size)) {
      perror("");
      wait(NULL);
      return -1;
    }

    test_getpeername(clientSocket, &serverAddr, addr_size);

    read(clientSocket, &buffer, sizeof(buffer));

    close(clientSocket);

    wait(NULL);
    printf("Success\n");
    return 0;
  } else {
    // Child / Server

    close(sv[0]);

    int welcomeSocket, newSocket;
    struct sockaddr_storage serverStorage;

    /*---- Create the socket. The three arguments are: ----*/
    /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
    welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);

    /*---- Configure settings of the server address struct ----*/
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(PORT);
    /* Set IP address to localhost */
    serverAddr.sin_addr.s_addr = inet_addr(ADDR);
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    /*---- Bind the address struct to the socket ----*/
    if (bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr))) {
      perror("");
      return -1;
    }

    /*---- Listen on the socket, with 5 max connection requests queued ----*/
    if(listen(welcomeSocket,5)) {
      perror("");
      return -1;
    }

    buffer[0] = '1';
    write(sv[1], buffer, 1);

    /*---- Accept call creates a new socket for the incoming connection ----*/
    addr_size = sizeof serverStorage;

    newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

    buffer[0] = '1';
    write(newSocket, buffer, 1);

    test_getpeername(welcomeSocket, &serverAddr, addr_size);

    // Wait for client to close remotely
    // This avoids the socket entering TIME_WAIT
    read(newSocket, buffer, sizeof(buffer));

    close(newSocket);
    close(welcomeSocket);
    return 0;
  }
}
