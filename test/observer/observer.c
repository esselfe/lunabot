/*
 * IRC Observer Client for lunabot integration tests
 *
 * A minimal C IRC client that connects to an IRC server (optionally via TLS),
 * joins a channel, and prints all PRIVMSG text to stdout. Used by the test
 * runner to capture lunabot's IRC output for assertion checking.
 *
 * Usage: observer [--server HOST] [--port PORT] [--nick NICK]
 *                 [--channel CHAN] [--tls|--no-tls] [--timeout SECS]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define LINE_BUF_SIZE 4096

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

/* Write a string to the IRC connection (SSL or plain) */
static int irc_write(SSL *ssl, int sock, const char *data, int use_tls) {
    size_t len = strlen(data);
    if (use_tls)
        return SSL_write(ssl, data, (int)len);
    else
        return (int)send(sock, data, len, 0);
}

/* Read from the IRC connection into buf, return bytes read */
static int irc_read(SSL *ssl, int sock, char *buf, int bufsize, int use_tls) {
    if (use_tls)
        return SSL_read(ssl, buf, bufsize);
    else
        return (int)recv(sock, buf, (size_t)bufsize, 0);
}

/* Extract PRIVMSG text from a line like ":nick!user@host PRIVMSG #channel :text" */
static void handle_line(const char *line, const char *channel,
                        SSL *ssl, int sock, int use_tls) {
    /* Handle PING */
    if (strncmp(line, "PING ", 5) == 0) {
        char pong[LINE_BUF_SIZE];
        snprintf(pong, sizeof(pong), "PONG %s\r\n", line + 5);
        irc_write(ssl, sock, pong, use_tls);
        return;
    }

    /* Look for PRIVMSG to our channel */
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "PRIVMSG %s :", channel);
    const char *match = strstr(line, pattern);
    if (match) {
        const char *text = match + strlen(pattern);
        printf("%s\n", text);
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    const char *server = "ergo";
    int port = 6697;
    const char *nick = "observer";
    const char *channel = "#test-lunabot";
    int use_tls = 1;
    int timeout_secs = 120;

    static const struct option long_opts[] = {
        {"server",  required_argument, NULL, 's'},
        {"port",    required_argument, NULL, 'p'},
        {"nick",    required_argument, NULL, 'n'},
        {"channel", required_argument, NULL, 'c'},
        {"tls",     no_argument,       NULL, 't'},
        {"no-tls",  no_argument,       NULL, 'T'},
        {"timeout", required_argument, NULL, 'o'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:n:c:tTo:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's': server = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 'n': nick = optarg; break;
        case 'c': channel = optarg; break;
        case 't': use_tls = 1; break;
        case 'T': use_tls = 0; break;
        case 'o': timeout_secs = atoi(optarg); break;
        default:
            fprintf(stderr, "Usage: observer [--server HOST] [--port PORT] "
                    "[--nick NICK] [--channel CHAN] [--tls|--no-tls] "
                    "[--timeout SECS]\n");
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Resolve server address */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int err = getaddrinfo(server, port_str, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "observer: getaddrinfo(%s): %s\n", server, gai_strerror(err));
        return 1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("observer: socket");
        freeaddrinfo(res);
        return 1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("observer: connect");
        close(sock);
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);

    fprintf(stderr, "observer: connected to %s:%d\n", server, port);

    /* TLS setup */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (use_tls) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            fprintf(stderr, "observer: SSL_CTX_new failed\n");
            close(sock);
            return 1;
        }
        /* Disable certificate verification for self-signed test certs */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            fprintf(stderr, "observer: SSL_connect failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return 1;
        }
        fprintf(stderr, "observer: TLS established\n");
    }

    /* Send NICK and USER */
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "NICK %s\r\n", nick);
    irc_write(ssl, sock, cmd, use_tls);

    snprintf(cmd, sizeof(cmd), "USER %s 0 * :Test Observer\r\n", nick);
    irc_write(ssl, sock, cmd, use_tls);

    /* Read loop with line buffering */
    char readbuf[LINE_BUF_SIZE];
    char linebuf[LINE_BUF_SIZE];
    int line_pos = 0;
    int joined = 0;
    time_t start_time = time(NULL);

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;

    while (running) {
        /* Check overall timeout */
        if (time(NULL) - start_time >= timeout_secs) {
            fprintf(stderr, "observer: timeout after %d seconds\n", timeout_secs);
            break;
        }

        int poll_ret = poll(&pfd, 1, 1000); /* 1-second poll timeout */
        if (poll_ret < 0) {
            if (errno == EINTR) continue;
            perror("observer: poll");
            break;
        }
        if (poll_ret == 0) continue; /* timeout, loop back to check overall timeout */

        int bytes = irc_read(ssl, sock, readbuf, sizeof(readbuf) - 1, use_tls);
        if (bytes <= 0) {
            fprintf(stderr, "observer: connection closed\n");
            break;
        }
        readbuf[bytes] = '\0';

        /* Process each byte, splitting on \r\n */
        for (int i = 0; i < bytes; i++) {
            if (readbuf[i] == '\r') continue;
            if (readbuf[i] == '\n') {
                linebuf[line_pos] = '\0';
                if (line_pos > 0) {
                    /* Check for RPL_WELCOME (001) to send JOIN */
                    if (!joined && strstr(linebuf, " 001 ")) {
                        snprintf(cmd, sizeof(cmd), "JOIN %s\r\n", channel);
                        irc_write(ssl, sock, cmd, use_tls);
                        joined = 1;
                        fprintf(stderr, "observer: joining %s\n", channel);
                    }
                    handle_line(linebuf, channel, ssl, sock, use_tls);
                }
                line_pos = 0;
            } else {
                if (line_pos < LINE_BUF_SIZE - 1)
                    linebuf[line_pos++] = readbuf[i];
            }
        }
    }

    /* Clean disconnect */
    irc_write(ssl, sock, "QUIT :done\r\n", use_tls);

    if (use_tls && ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) SSL_CTX_free(ctx);
    close(sock);

    return 0;
}
