#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <assert.h>
#include <mutex>

#include <iostream>
#include <thread>
#include <list>
#include <string>
#include <unordered_map>
#include <atomic>
#include <signal.h>

#define MAX_THREADS 16

#define DATA_BLOCK_SIZE 65536
#define LISTEN_BACKLOG 512
#define SHORT_RESPONSE_SIZE 100

// parameters
unsigned int max_buf_size = 4096;
bool dump_io_stats = true;
bool short_response = true;
bool multiport = false;
unsigned int nr_threads = 1;
unsigned int nr_queues = 1;
unsigned int message_bytes = 128;
std::string server_ip_str = "192.168.6.2"; // FXIME: this is not used in this test
uint16_t server_port = 50000;

std::list<std::thread> threads;

uint64_t total_in = 0;
uint64_t total_out = 0;
static std::atomic<uint64_t> total_recv_bytes[MAX_THREADS] = {};
uint64_t prev_total_recv_bytes[MAX_THREADS] = {};
static std::atomic<uint64_t> total_resp_bytes[MAX_THREADS] = {};
uint64_t prev_total_resp_bytes[MAX_THREADS] = {};
static std::atomic<uint32_t> avg_nr_events(0);

struct connection {
    int fd;

    const ssize_t MESSAGE_SIZE;
    const ssize_t MAX_BUF_SIZE;

    const bool short_response;

    char *buf;
    ssize_t buf_len;
    char *check_pos;
    char *recv_pos;

    ssize_t bytes_inbound;
    ssize_t short_bytes_sent;
    bool has_epoll_out;

    connection(int fd, unsigned int message_size, unsigned int max_buf_size, bool short_response)
        : fd(fd), MESSAGE_SIZE(message_size), MAX_BUF_SIZE(max_buf_size), short_response(short_response) {

        assert(MAX_BUF_SIZE >= MESSAGE_SIZE);
        assert(MAX_BUF_SIZE % MESSAGE_SIZE == 0);

        buf = (char *)calloc(2, MAX_BUF_SIZE);
        buf_len = 2 * MAX_BUF_SIZE;
        recv_pos = check_pos = buf;

        bytes_inbound = 0;
        short_bytes_sent = 0;
        has_epoll_out = false;
    }
    ~connection() {
        free(buf);
    }
};

std::mutex conn_fds_mtx;
std::list<int> conn_fds;

static inline int listen_socket(int fd, int epfd, uint32_t events)
{
    struct epoll_event ev;
    if (events & EPOLLERR) {
        fprintf(stderr, "Error on listen socket\n");
        close(fd);
        return -1;
    }
    while (events & EPOLLIN) {
        int newfd = accept(fd, NULL, NULL);
        if (newfd < 0) {
            fprintf(stdout, "accept() returned %d errno=%d\n", newfd, errno);
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "Failed to accept new connection\n");
            return -1;
        }
        printf("Connection accpeted: %d\n", newfd);

        int flags = fcntl(newfd, F_GETFL, 0);
        if (flags < 0 || fcntl(newfd, F_SETFL, flags | O_NONBLOCK)) {
            fprintf(stderr, "Failed to set non-blocking\n");
            close(newfd);
            continue;
        }

        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
        ev.data.ptr = new connection(newfd, message_bytes, max_buf_size, short_response);
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, newfd, &ev)) {
            fprintf(stderr, "Failed to add newfd to epoll\n");
            delete (struct connection *)ev.data.ptr;
            close(newfd);
            continue;
        }

        conn_fds_mtx.lock();
        conn_fds.push_back(newfd);
        conn_fds_mtx.unlock();
    }
    return 0;
}

static inline int connection_send(unsigned int tid, struct connection *c)
{
    int need_epoll_out = 0;
    ssize_t ret;

    if (!c->short_response) {
        while (c->bytes_inbound > 0) {
            ssize_t send_len;
            if (c->recv_pos > c->check_pos) {
                send_len = c->recv_pos - c->check_pos;
            } else {
                send_len = c->buf + c->MAX_BUF_SIZE - c->check_pos;
            }
            send_len = std::min((ssize_t)DATA_BLOCK_SIZE, send_len);

            ret = write(c->fd, c->check_pos, send_len);
            if (ret > 0) {
                c->bytes_inbound -= ret;
                c->check_pos += ret;
                total_resp_bytes[tid].fetch_add(ret);
                if (c->check_pos >= c->buf + c->MAX_BUF_SIZE) {
                    c->check_pos = c->buf;
                }
            } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                need_epoll_out = 1;
                break;
            } else if (ret < 0 && (errno == EINTR)) {
                continue;
            } else {
                return -1;
            }
        }

        return need_epoll_out;
    } else {
        while (c->bytes_inbound >= c->MESSAGE_SIZE) {
            ssize_t send_len = SHORT_RESPONSE_SIZE - c->short_bytes_sent;
            ret = write(c->fd, c->check_pos + c->short_bytes_sent, send_len);
            if (ret > 0) {
                c->short_bytes_sent += ret;
                total_resp_bytes[tid].fetch_add(ret);
                if (c->short_bytes_sent == SHORT_RESPONSE_SIZE) {
                    c->bytes_inbound -= c->MESSAGE_SIZE;
                    c->check_pos += c->MESSAGE_SIZE;
                    if (c->check_pos >= c->buf + c->MAX_BUF_SIZE) {
                        c->check_pos -= c->MAX_BUF_SIZE;
                    }
                    c->short_bytes_sent = 0;
                }
            } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                need_epoll_out = 1;
                break;
            } else if (ret < 0 && errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        }
    }
    return need_epoll_out;
}

static inline int connection_recv(unsigned int tid, struct connection *c)
{
    ssize_t ret;
    while (c->bytes_inbound < c->MAX_BUF_SIZE) {
        ssize_t recv_len;
        if (c->check_pos > c->recv_pos) {
            recv_len = c->check_pos - c->recv_pos;
        } else {
            recv_len = c->buf + c->MAX_BUF_SIZE - c->recv_pos;
        }
        recv_len = std::min(recv_len, (ssize_t)DATA_BLOCK_SIZE);

        ret = read(c->fd, c->recv_pos, recv_len);
        if (ret > 0) {
            c->recv_pos += ret;
            assert(c->recv_pos <= c->buf + c->MAX_BUF_SIZE);
            if (c->recv_pos - c->buf == c->MAX_BUF_SIZE) {
                c->recv_pos = c->buf;
            }
            c->bytes_inbound += ret;

            assert((c->check_pos - c->buf) % c->MESSAGE_SIZE == 0);
            total_recv_bytes[tid].fetch_add(ret);
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else if (ret < 0 && (errno == EINTR)) {
            continue;
        } else {
            return -1;
        }

    }

    return 0;
}

static inline int connection_events(unsigned int tid, struct connection *c, uint32_t events)
{
    if (events & EPOLLIN) {
        int ret = connection_recv(tid, c);
        if (ret < 0)
            return ret;
    }

    return connection_send(tid, c);
}

void thread_func(unsigned int tid)
{
    int epfd;
    struct epoll_event ev, events[256];
    struct in_addr server_ip_addr;
    uint16_t t_server_port = server_port + tid;
    // uint16_t t_server_port = server_port;
    struct connection *c;
    
    assert(inet_pton(AF_INET, server_ip_str.c_str(), &server_ip_addr) == 1);

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        fprintf(stderr, "Failed to create socket\n");
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(t_server_port);
    server_addr.sin_addr.s_addr = server_ip_addr.s_addr;

    if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Failed to bind to server\n");
        close(fd);
        return;
    }

    if (listen(fd, LISTEN_BACKLOG)) {
        fprintf(stderr, "Failed to listen\n");
        close(fd);
        return;
    }
    printf("Server thread#%u listen on %s:%d\n", tid, server_ip_str.c_str(), t_server_port);

    epfd = epoll_create1(0);

    if (epfd < 0) {
        fprintf(stderr, "Failed to create epoll\n");
        close(fd);
        return;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = NULL;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        fprintf(stderr, "Failed to add fd to epoll\n");
        close(fd);
        close(epfd);
        return;
    }

    while (1) {

        int nfds = epoll_wait(epfd, events, 128, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "epoll_wait failed\n");
            close(epfd);
            close(fd);
            return;
        }
        if (nfds) avg_nr_events.store((avg_nr_events.load() + nfds) / 2);
        for (int i = 0; i < nfds; i++) {
            c = (struct connection *)events[i].data.ptr;

            if (c == NULL) {
                if (listen_socket(fd, epfd, events[i].events))
                    abort();
                continue;
            }

            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                conn_fds_mtx.lock();
                conn_fds.remove(c->fd);
                conn_fds_mtx.unlock();
                // remove from epoll
                if (epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL) < 0) {
                    fprintf(stderr, "Failed to remove erronous fd from epoll\n");
                    close(c->fd);
                    delete c;
                    close(epfd);
                    return;
                }
                close(c->fd);
                delete c;
                continue;
            }

            int ret = connection_events(tid, c, events[i].events);

            if (ret < 0) {
                conn_fds_mtx.lock();
                conn_fds.remove(c->fd);
                conn_fds_mtx.unlock();
                // remove from epoll
                if (epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL) < 0) {
                    fprintf(stderr, "Failed to remove erronous fd from epoll\n");
                    close(c->fd);
                    delete c;
                    close(epfd);
                    return;
                }
                close(c->fd);
                delete c;
                continue;
            }

            if (ret == 1 && !c->has_epoll_out) {
                ev.events = EPOLLIN | EPOLLOUT;
                ev.data.ptr = c;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
                    fprintf(stderr, "Failed to add fd to epoll\n");
                    close(c->fd);
                    conn_fds_mtx.lock();
                    conn_fds.remove(c->fd);
                    conn_fds_mtx.unlock();
                    delete c;
                    close(epfd);
                    return;
                }
                c->has_epoll_out = true;
            } else if (ret == 0 && c->has_epoll_out)  {
                ev.events = EPOLLIN;
                ev.data.ptr = c;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
                    fprintf(stderr, "Failed to add fd to epoll\n");
                    close(c->fd);
                    conn_fds_mtx.lock();
                    conn_fds.remove(c->fd);
                    conn_fds_mtx.unlock();
                    close(epfd);
                    return;
                }
                c->has_epoll_out = false;
            }
        }

    }

    close(epfd);
    close(fd);
    for (auto &fd : conn_fds) {
        close(fd);
    }
}

int parse_args(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "t:q:df:b:i:p:sl:m")) != -1) {
        switch (opt) {
            case 'b':
                message_bytes = std::stoi(optarg);
                break;
            case 'i':
                server_ip_str = optarg;
                break;
            case 'p':
                server_port = std::stoi(optarg);
                break;
            case 'd':
                dump_io_stats = true;
                break;
            case 'q':
                nr_queues = std::stoi(optarg);
                break;
            case 't':
                nr_threads = std::stoi(optarg);
                break;
            case 'l':
                max_buf_size = std::stoi(optarg);
                break;
            case 's':
                short_response = false;
                break;
            case 'm':
                multiport = true;
                break;
            default:
                std::cout << "Usage: " << argv[0] << 
                    " [-t nr_threads, default:1]" <<
                    " [-l max_buf_size, default:4096]"
                    " [-q nr_queues, default:1]" <<
                    " [-b bytes, default:128]" << 
                    " [-i server_ip, default:192.168.6.2]" <<
                    " [-p server_port, default:50000]" << 
                    " [-s disable short_response, default:true]" << 
                    " [-m enable multiport, default: false]" <<
                    " [-d dump_io_stats]" << std::endl;
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{

    signal(SIGPIPE, SIG_IGN);

    if (parse_args(argc, argv))
    {
        std::cout << "Failed to parse arguments." << std::endl;
        exit(EXIT_FAILURE);
    }

    if (multiport == false && nr_threads > 1) {
        fprintf(stderr, "enable multiport when using multiple threads");
        return -1;
    }

    if (message_bytes == 0 || message_bytes > 2000000) {
        fprintf(stderr, "not allowed size");
        return -1;
    }

    if (message_bytes > max_buf_size) {
        fprintf(stderr, "message_bytes larger than max_buf_size");
        return -1;
    }

    if (max_buf_size % message_bytes != 0) {
        fprintf(stderr, "max_buf_size should be multiple of message_bytes");
        return -1;
    }

    if (message_bytes < SHORT_RESPONSE_SIZE && short_response == true) {
        fprintf(stderr, "short response not allowed when message size is under 100 bytes");
        return -1;
    }


    if (nr_threads == 0 || nr_threads > MAX_THREADS) {
        fprintf(stderr, "nr_threads must be between 1 and %d\n", MAX_THREADS);
        return -1;
    }
    
    for (unsigned int i = 0; i < nr_threads; i++) {
        threads.push_back(std::thread(thread_func, i));
    }

    if (dump_io_stats) {
        std::thread([]() {
            while (1) {
                sleep(1);

                uint64_t _in = 0;
                uint64_t _out = 0;

                for (unsigned int i = 0; i < nr_threads; i++) {
                    _in += total_recv_bytes[i].load() - prev_total_recv_bytes[i];
                    _out += total_resp_bytes[i].load() - prev_total_resp_bytes[i];
                    prev_total_recv_bytes[i] = total_recv_bytes[i].load();
                    prev_total_resp_bytes[i] = total_resp_bytes[i].load();
                }
                total_in += _in;
                total_out += _out;

                size_t nr_conn_fds;
                {
                    std::lock_guard<std::mutex> lock(conn_fds_mtx);
                    nr_conn_fds = conn_fds.size();
                }

                printf("Throughput In/Out(%.2f/%.2f Gbps)(%.2f Kops) conn#(%lu), avg_nr_events(%u), total_recv(%luB), total_resp(%luB)\n", 
                    _in * 8.0 / 1e9, _out * 8.0 / 1e9, _in / message_bytes / 1e3,
                    nr_conn_fds, avg_nr_events.load(), total_in, total_out);
            }
        }).detach();
    }

    for (auto &t : threads) {
        t.join();
    }

    return 0;
}
