#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <net/if.h>

#include <linux/if_tun.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <sys/stat.h>

#include <fcntl.h>

#include <arpa/inet.h>

#include <sys/select.h>

#include <sys/time.h>

#include <signal.h>

#include <errno.h>

#include <stdarg.h>

#include <iostream>

#include <stdio.h>

#include <stdlib.h>

#include <unistd.h>

#include <errno.h>

#include <string.h>

#include <fcntl.h>

#include <netdb.h>

#include <sys/types.h>

#include <sys/stat.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdint.h>

#include <time.h>

#include <stdarg.h>

#include <string.h>

#include <sched.h>


using namespace std;

#pragma GCC diagnostic ignored "-Wwrite-strings"

#define BUFSIZE 2000 // must be >= 1500
#define CLIENT 0
#define SERVER 1
#define PORT 55559
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

#pragma pack(push)
#pragma pack(1)

typedef struct tIPPackHead {
    BYTE ver_hlen;
    BYTE byTOS;
    WORD wPacketLen;
    WORD wSequence;
    union {
        WORD Flags;
        WORD FragOf;
    };
    BYTE byTTL;
    BYTE byProtocolType;
    WORD wHeadCheckSum;
    DWORD dwIPSrc;
    DWORD dwIPDes;
    // BYTE Options;
}
IP_HEAD;

#pragma pack(pop)

int debug;
char * progname;
int cnt;

int print_ts()
{
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

    timer = time(NULL);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    puts(buffer);

    return 0;
}

void do_debug(char * msg, ...) {
    va_list argp;

    if (debug) {
        print_ts();
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

void my_err(char * msg, ...) {
    va_list argp;

    print_ts();
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}

typedef struct rand_seed {
    uint32_t Q[4096];
    uint32_t c;
}
rand_seed;

uint32_t init_rand(rand_seed * rs) {
    int i;
    uint32_t x = 'a';
    uint32_t PHI = 0x9e3779b9;
    time_t t = 0x44189; // time(NULL);

    PHI = ((uint32_t) t / 3600 * 3600) % PHI;
    x = (PHI % (2 * 3 * 5 * 7 * 11 * 13 - 1) % 27) + x;
    rs -> c = 362436;
    rs -> Q[0] = x & 0xffffff;
    rs -> Q[1] = (x + PHI) & 0xffffff;
    rs -> Q[2] = (x + PHI + PHI) & 0xffffff;
    for (i = 3; i < 4096; i++) {
        rs -> Q[i] = rs -> Q[i - 3] ^ rs -> Q[i - 2] ^ PHI ^ i;
    }

    return PHI;
}

uint32_t rand_cmwc0(rand_seed * rs) {
    uint32_t t, a = 18782L;
    uint32_t i = rs -> c;
    uint32_t x, r = 0xfffffe;

    i = (i + 1) % 4096;
    t = a * rs -> Q[i] + rs -> c;
    rs -> c = (t >> 16) & 0xffffff;
    x = t + rs -> c;
    if (x < rs -> c) {
        x++;
        rs -> c++;
    }

    return (rs -> Q[i] = r ^ x);
}

uint32_t rand_cmwc(rand_seed * rs, int n) {
    uint32_t t, a = 18782L;
    uint32_t i = rs -> c;

    i = (i + n) % 4096;
    t = a * rs -> Q[i] + rs -> c;
    return (t >> 16) & 0xffffff;
}

void encrypt0(char * buff, int len, rand_seed * rs) {
    int i = 0;

    for (i = 0; i < len; i++) {
        unsigned char x = rand_cmwc(rs, i) & 0xff;
        unsigned char * ch = (unsigned char * )(buff + i);
        * ch ^= x;
    }
}

uint8_t key[17] = {
    0x44,
    0x44,
    0x11,
    0x88,
    0x99,
    0x18,
    0x39,
    0x17,
    0xaa,
    0xcc,
    0x1a,
    0x12,
    0x23,
    0x66,
    0x88,
    0x06,
    0x00
};

rand_seed rs;

int g_tap_fd = -1;

// extern "C" {

extern int aes_encrypt_ecb_padding(uint8_t * data, int len, int size, uint8_t * key);
 
extern int aes_decrypt_ecb_padding(uint8_t * data, int len, uint8_t * key);

// }

int _encrypt(char * buff, int len) {
	// return aes_encrypt_ecb_padding((uint8_t*) buff, len, 2000, key);
	encrypt0(buff, len, &rs);
	return len;
}

int _decrypt(char * buff, int len) {
        // return aes_decrypt_ecb_padding((uint8_t*) buff, len, key);
	encrypt0(buff, len, &rs);
	return len;
}

int DecodeIP(char * buf, int len) {
    int n = len;
    if (n >= sizeof(IP_HEAD)) {
        IP_HEAD iphead;
        iphead = * (IP_HEAD * ) buf;
    }
    return 0;
}

int tun_alloc(char * dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    char * clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        my_err("Opening /dev/net/tun");
        return fd;
    }
    memset( & ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    if ( * dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void * ) & ifr)) < 0) {
        my_err("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

int cread(int fd, char * buf, int n) {
    int nread = 0;

    if ((nread = read(fd, buf, n)) < 0) {
        perror("Reading data");
    }
    return nread;
}

int cwrite(int fd, char * buf, int n) {
    int nwrite = 0;

    if (n > 0 && fd != g_tap_fd) {
        n = _encrypt(buf, n);
    }
    if ((nwrite = write(fd, buf, n)) < 0) {
        perror("Writing data");
    }
    return nwrite;
}

int read_n(int fd, char * buf, int n) {
    int nread, left = n;

    while (left > 0) {
        if ((nread = cread(fd, buf, left)) == 0) {
            return 0;
        } else {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}

int read_ipv4_len_left(int fd, char * buf) {
    int nread;

    nread = read_n(fd, buf, sizeof(IP_HEAD));
    if (nread == 0) {
        return 0;
    }
    IP_HEAD iphead;
    iphead = * (IP_HEAD * ) buf;
    return ntohs(iphead.wPacketLen) - sizeof(IP_HEAD);
}

void usage(void) {
    fprintf(stderr, "Version: 2020.11.20-no_aes\nUsage:\n");
    fprintf(stderr,
        "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n",
        progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr,
        "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr,
        "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55559\n");
    fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}

int main(int argc, char * argv[]) {
    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int maxfd;
    int nread, nwrite, plength;
    char buffer[BUFSIZE];
    IP_HEAD * ip_head;
    struct sockaddr_in local, remote;
    char remote_ip[16] = "";
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1;
    int pair_ok = -1;
    unsigned long int tap2net = 0, net2tap = 0;
    long long ts_out = -1, ts_in = -1;

    init_rand( & rs);

    progname = argv[0];

    while ((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
        switch (option) {
        case 'd':
            debug = 1;
            break;
        case 'h':
            usage();
            break;
        case 'i':
            strncpy(if_name, optarg, IFNAMSIZ - 1);
            break;
        case 's':
            cliserv = SERVER;
            break;
        case 'c':
            cliserv = CLIENT;
            strncpy(remote_ip, optarg, 15);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'u':
            flags = IFF_TUN;
            break;
        case 'a':
            flags = IFF_TAP;
            break;
        default:
            my_err("Unknown option %c\n", option);
            usage();
        }
    }

    argv += optind;
    argc -= optind;

    if (argc > 0) {
        my_err("Too many options!\n");
        usage();
    }

    if ( * if_name == '\0') {
        my_err("Must specify interface name!\n");
        usage();
    } else if (cliserv < 0) {
        my_err("Must specify client or server mode!\n");
        usage();
    } else if ((cliserv == CLIENT) && ( * remote_ip == '\0')) {
        my_err("Must specify server address!\n");
        usage();
    }

    if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    do_debug("Successfully connected to interface %s\n", if_name);

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        my_err("socket()");
        exit(1);
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char * ) & optval,
            sizeof(optval)) < 0) {
        my_err("setsockopt()");
        exit(1);
    }

    memset( & local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr * ) & local, sizeof(local)) < 0) {
        my_err("bind()");
        exit(1);
    }

    if (cliserv == CLIENT) {
        memset( & remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_addr.s_addr = inet_addr(remote_ip);
        remote.sin_port = htons(port);

        if (connect(sock_fd, (struct sockaddr * ) & remote, sizeof(remote)) < 0) {
            my_err("connect()");
            exit(1);
        }
        printf("CLIENT: Connected to server %s:%d\n",
            inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
    }

    net_fd = sock_fd;
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

    g_tap_fd = tap_fd;

    while (1) {
        int ret;
        fd_set rd_set;
        struct timeval tv;

        if (cliserv == CLIENT) {
            long ts = (int) time(NULL);

            if (ts_in < 0 || ts_in + 5 < ts) {
                * buffer = 0x45;
                ip_head = (IP_HEAD * ) buffer;
                ip_head -> dwIPSrc = ip_head -> dwIPDes = -1;
                nwrite = cwrite(net_fd, buffer, sizeof(IP_HEAD));
                if (nwrite == sizeof(IP_HEAD)) {
                    ts_out = ts_in = ts;
                }
            }
        }

        FD_ZERO( & rd_set);
        FD_SET(tap_fd, & rd_set);
        FD_SET(net_fd, & rd_set);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        ret = select(maxfd + 1, & rd_set, NULL, NULL, & tv);

        if (ret < 0 && errno == EINTR) {
            continue;
        }

        if (ret < 0) {
            my_err("select()");
        }

        if (FD_ISSET(tap_fd, & rd_set)) {
            nread = cread(tap_fd, buffer, BUFSIZE);
            tap2net++;
            if (pair_ok != 1 && cliserv == SERVER) {
                // NOOP
            } else if (nread > 0) {
                nwrite = cwrite(net_fd, buffer, nread);
                ts_out = (int) time(NULL);
            }
        }

        if (FD_ISSET(net_fd, & rd_set)) {
            struct sockaddr_in cliaddr;
            unsigned int len = sizeof(cliaddr);

            nread = recvfrom(net_fd, (char * ) buffer, BUFSIZE,
                MSG_DONTWAIT, (struct sockaddr * ) & cliaddr, & len);
            net2tap++;

            if (nread > 0) {
		nread = _decrypt(buffer, nread);
	    }

            if (nread >= (int) sizeof(IP_HEAD)) {
                ip_head = (IP_HEAD * ) buffer;
                if ((char)( * buffer) == 0x45 && ip_head -> dwIPSrc == -1 &&
                    ip_head -> dwIPDes == -1) {
                    if (cliserv == SERVER) {
                        if (connect(net_fd, (struct sockaddr * ) & cliaddr,
                                sizeof(cliaddr)) < 0) {
                            pair_ok = 0;
                            my_err("connect to pair error!");
                        } else {
                            pair_ok = 1;
                            nwrite = cwrite(net_fd, (char * ) buffer, nread);
                            do_debug("SERVER: Connected to pair %s:%d\n",
                                inet_ntoa(cliaddr.sin_addr),
                                ntohs(cliaddr.sin_port));
                        }
                    }
                    ts_in = (int) time(NULL);
                    nread = 0;
                }
            }
            if (nread > 0) {
                nwrite = cwrite(tap_fd, (char * ) buffer, nread);
            }
        }
    }

    return (0);
}
