/*
 * RUN: %{cc} %s -o %t1
 * RUN: echo "Success" >  %t1.expected
 * RUN: %{timeout} 2 %{sbr} %t1 &> %t1.actual
 * RUN: diff %t1.actual %t1.expected
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#define TO_SEND_1 "Test contents 1"
#define TO_SEND_2 "Test contents 2"
#define TO_SEND_3 "Test contents 3"

struct metadata {
    int fd;
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

// There's no libc API for sendmmsg or recvmmsg
static int sendmmsg(int fd, struct mmsghdr *mmsg, unsigned vlen, unsigned flags) {
    return syscall(__NR_sendmmsg, fd, mmsg, vlen, flags, NULL);
}

/*
   This test forks two processes and sends two messages from one to the other,
   testing syscalls sendmmsg and recvmmsg.
   This test fails if:
   - sendmmsg does not set field mmsg.msg_hdr at all
   - sendmmsg does not set field mmsg.msg_hdr to the same value on the leader
     and followers
   - the sent messages have a different content than expected
   - the sent messages have a different content size in the leader and followers
*/
int main() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        printf("Failed to create Unix-domain socket pair\n");
        return -1;
    }

    if (fork()) {  // in parent
        close(sv[1]);
        int sock = sv[0];

        char * to_send1 = TO_SEND_1;
        char * to_send2 = TO_SEND_2;
        char * to_send3 = TO_SEND_3;

        struct mmsghdr mmsg[3];
        struct iovec msg1, msg2, msg3;
        int retval;

        memset(&msg1, 0, sizeof(msg1));
        msg1.iov_base = to_send1;
        msg1.iov_len  = sizeof(TO_SEND_1);

        memset(&msg2, 0, sizeof(msg2));
        msg2.iov_base = to_send2;
        msg2.iov_len  = sizeof(TO_SEND_2);

        memset(&msg3, 0, sizeof(msg3));
        msg3.iov_base = to_send3;
        msg3.iov_len  = sizeof(TO_SEND_3);

        memset(mmsg, 0, sizeof(mmsg));
        mmsg[0].msg_hdr.msg_iov    = &msg1;
        mmsg[0].msg_hdr.msg_iovlen = 1;
        mmsg[0].msg_len            = 0;
        mmsg[1].msg_hdr.msg_iov    = &msg2;
        mmsg[1].msg_hdr.msg_iovlen = 1;
        mmsg[1].msg_len            = 0;
        mmsg[2].msg_hdr.msg_iov    = &msg3;
        mmsg[2].msg_hdr.msg_iovlen = 1;
        mmsg[2].msg_len            = 0;

        retval = sendmmsg(sock, mmsg, (sizeof(mmsg) / sizeof(*mmsg)), 0);

        {
          char buffer[1024];

          assert(mmsg[0].msg_len != 0);
          snprintf(buffer, sizeof(buffer), "%d", mmsg[0].msg_len);
          open(buffer, O_RDONLY);

          assert(mmsg[1].msg_len != 0);
          snprintf(buffer, sizeof(buffer), "%d", mmsg[1].msg_len);
          open(buffer, O_RDONLY);

          assert(mmsg[2].msg_len != 0);
          snprintf(buffer, sizeof(buffer), "%d", mmsg[2].msg_len);
          open(buffer, O_RDONLY);
        }

        return 0;
    } else { // in child
        close(sv[0]);
        int sock = sv[1];

        char buffer[1024];
        struct iovec iov;
        struct msghdr msghdr;
        int retval;

        memset(&iov, 0, sizeof(iov));
        iov.iov_base = buffer;
        iov.iov_len  = sizeof(buffer);

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_iov    = &iov;
        msghdr.msg_iovlen = 1;

        retval = recvmsg(sock, &msghdr, 0);
        assert(retval > 0);
        assert(!strncmp(buffer, TO_SEND_1, sizeof(TO_SEND_1)));
        snprintf(buffer, sizeof(buffer), "%d", retval);
        open(buffer, O_RDONLY);

        retval = recvmsg(sock, &msghdr, 0);
        assert(retval > 0);
        assert(!strncmp(buffer, TO_SEND_2, sizeof(TO_SEND_2)));
        snprintf(buffer, sizeof(buffer), "%d", retval);
        open(buffer, O_RDONLY);

        retval = recvmsg(sock, &msghdr, 0);
        assert(retval > 0);
        assert(!strncmp(buffer, TO_SEND_3, sizeof(TO_SEND_3)));
        snprintf(buffer, sizeof(buffer), "%d", retval);
        open(buffer, O_RDONLY);

        printf("Success\n");

        return 0;
    }

    // Dead code
    assert(0);
    return 1;
}
