#include <arpa/inet.h>
#include <cerrno>
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
#include <cstring>
#include <random>
#include <functional>

#define MAX_THREADS 16

#define DATA_BLOCK_SIZE 65536
#define SHORT_RESPONSE_SIZE 100

unsigned int max_buf_size = 4096;
int wait_seconds = 0;
bool multiport = false;
bool dump_io_stats = false;
bool short_response = true;
unsigned int max_outstanding = 1;
unsigned int nr_flows = 1;
unsigned int nr_threads = 1;
unsigned int nr_queues = 1;
unsigned int message_bytes = 128;
std::string server_ip_str = "192.168.6.2";
uint16_t server_port = 50000;

std::list<std::thread> threads;
std::mutex conn_fds_mtx;
std::list<int> conn_fds;

std::mutex mtx;
static unsigned int ready_threads = 0;

uint64_t total_out = 0;
uint64_t total_in = 0;
static std::atomic<uint64_t> total_req_bytes[MAX_THREADS] = {};
uint64_t prev_total_req_bytes[MAX_THREADS] = {};
static std::atomic<uint64_t> total_resp_bytes[MAX_THREADS] = {};
uint64_t prev_total_resp_bytes[MAX_THREADS] = {};
static std::atomic<uint32_t> avg_nr_events(0);

static void fill_random(uint8_t *buf, size_t len)
{
    static thread_local std::mt19937 rng(
        0x12345678u ^ std::hash<std::thread::id>{}(std::this_thread::get_id())
    );

    std::uniform_int_distribution<unsigned int> dist(0, 255);

    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<uint8_t>(dist(rng));
    }
}

struct connection {
    int fd;
    bool no_epoll_out;

    const unsigned int MAX_OUTSTANDING;

    const bool short_response;

    const unsigned int SEND_MSG_SIZE;
    char *send_buf;
    ssize_t send_buf_len;
    ssize_t total_msg_size;
    char *send_buf_check_pos;
    char *send_buf_send_pos;

    ssize_t outstanding_bytes;
    ssize_t num_outstanding_msg;

    const unsigned int RECV_MSG_SIZE;
    char *recv_buf;
    ssize_t recv_buf_len;
    char *recv_buf_pos;
    char *recv_check_pos;

    connection(int fd, unsigned int send_msg_size, unsigned int max_outstanding, bool short_response)
        : fd(fd), MAX_OUTSTANDING(max_outstanding), short_response(short_response), SEND_MSG_SIZE(send_msg_size), RECV_MSG_SIZE(short_response ? SHORT_RESPONSE_SIZE : send_msg_size) {

        no_epoll_out = false;

        total_msg_size = SEND_MSG_SIZE * MAX_OUTSTANDING;
        send_buf_len = 2 * total_msg_size;
        send_buf = (char *)calloc(1, send_buf_len);
        fill_random((uint8_t *)send_buf, total_msg_size);
        memcpy(send_buf + total_msg_size, send_buf, total_msg_size);
        send_buf_check_pos = send_buf;
        send_buf_send_pos = send_buf;
        outstanding_bytes = 0;
        num_outstanding_msg = 0;

        recv_buf_len = 2 * RECV_MSG_SIZE * MAX_OUTSTANDING;
        recv_buf = (char *)calloc(1, recv_buf_len);
        recv_buf_pos = recv_buf;
        recv_check_pos = recv_buf;
        
    }
    ~connection() {
        free(send_buf);
        free(recv_buf);
    }
};

static inline int connection_send(unsigned int tid, struct connection *c)
{
    ssize_t ret;
    int need_epoll_out = 0;
    // Transmit messages as much as possible through this connection until we reach max_outstanding or no buffer space
    assert(c->total_msg_size >= c->outstanding_bytes);

    ssize_t prev_outstanding_bytes = c->outstanding_bytes;
    while (c->outstanding_bytes < c->total_msg_size ) {
        unsigned int pending_bytes = c->total_msg_size - c->outstanding_bytes;
        ret = write(c->fd, c->send_buf_send_pos, std::min(pending_bytes, (unsigned int)DATA_BLOCK_SIZE));
        if (ret > 0) {
            c->send_buf_send_pos += ret;
            if (c->send_buf_send_pos >= c->send_buf + c->total_msg_size) {
                c->send_buf_send_pos -= c->total_msg_size;
            }

            c->outstanding_bytes += ret;
            total_req_bytes[tid].fetch_add(ret);
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            need_epoll_out = 1;
            break;
        } else if (ret < 0 && (errno == EINTR)) {
            continue;
        } else {
            return -1;
        }
    }

    if (c->short_response)
        c->num_outstanding_msg += c->outstanding_bytes / c->SEND_MSG_SIZE - prev_outstanding_bytes / c->SEND_MSG_SIZE;

    return need_epoll_out;
}

static inline int connection_recv(unsigned int tid, struct connection *c)
{
    ssize_t ret;
    
    if (c->short_response) {
        while (c->outstanding_bytes > 0) {
            // ssize_t complete_outstanding_msgs = c->outstanding_bytes / c->SEND_MSG_SIZE;
            ssize_t partial_recv_bytes = c->recv_buf_pos - c->recv_check_pos;
            if (partial_recv_bytes > 0 && c->recv_check_pos != c->recv_buf) {
                memmove(c->recv_buf, c->recv_check_pos, partial_recv_bytes);
                c->recv_check_pos = c->recv_buf;
                c->recv_buf_pos = c->recv_buf + partial_recv_bytes;
            } else if (partial_recv_bytes == 0) {
                c->recv_check_pos = c->recv_buf;
                c->recv_buf_pos = c->recv_buf;
            }

            ssize_t outstanding_resp_bytes = c->num_outstanding_msg * SHORT_RESPONSE_SIZE - partial_recv_bytes;
            if (outstanding_resp_bytes <= 0)
                break;

            ssize_t recv_buf_avail = c->recv_buf + c->recv_buf_len - c->recv_buf_pos;
            ret = read(c->fd, c->recv_buf_pos,
                       std::min(std::min(outstanding_resp_bytes, recv_buf_avail), (ssize_t)DATA_BLOCK_SIZE));

            if (ret > 0) {
                c->recv_buf_pos += ret;
                unsigned int num_responses = (c->recv_buf_pos - c->recv_check_pos) / SHORT_RESPONSE_SIZE;
                
                for (unsigned int i = 0; i < num_responses; i++) {
                    if (memcmp(c->send_buf_check_pos, c->recv_check_pos, SHORT_RESPONSE_SIZE) != 0) {
                        assert(false);
                    }

                    c->send_buf_check_pos += c->SEND_MSG_SIZE;
                    c->recv_check_pos += SHORT_RESPONSE_SIZE;
                }

                if (c->send_buf_check_pos >= c->send_buf + c->total_msg_size) {
                    c->send_buf_check_pos -= c->total_msg_size;
                }

                c->num_outstanding_msg -= num_responses;
                c->outstanding_bytes -= num_responses * c->SEND_MSG_SIZE;

            
                total_resp_bytes[tid].fetch_add(ret);
            } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // no more message to recv
                break;
            } else if (ret < 0 && errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        }

    } else {
        while (c->outstanding_bytes > 0) {
            ret = read(c->fd, c->recv_buf_pos, std::min(c->outstanding_bytes, (long)DATA_BLOCK_SIZE));
            if (ret > 0) {
                // check
                if (memcmp(c->send_buf_check_pos, c->recv_buf_pos, ret) != 0) {
                    assert(false);
                }
                // update positions
                c->send_buf_check_pos += ret;
                if (c->send_buf_check_pos >= c->send_buf + c->total_msg_size) {
                    c->send_buf_check_pos -= c->total_msg_size;
                }
                c->recv_buf_pos += ret;
                if (c->recv_buf_pos >= c->recv_buf + c->total_msg_size) {
                    c->recv_buf_pos -= c->total_msg_size;
                }

                c->outstanding_bytes -= ret;

                total_resp_bytes[tid].fetch_add(ret);
            } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // no more message to recv
                break;
            } else if (ret < 0 && errno == EINTR) {
                continue;
            } else {
                return -1;
            }
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
    struct connection *c;
    int epfd;
    struct epoll_event ev, events[256];
    struct in_addr server_ip_addr;
    uint16_t t_server_port;
    if (multiport)
        t_server_port = server_port + tid;
    else
        t_server_port = server_port;
    unsigned int t_nr_flows = nr_flows / nr_threads;
    if (t_nr_flows == 0) {
        t_nr_flows = 1;
    }
    
    assert(inet_pton(AF_INET, server_ip_str.c_str(), &server_ip_addr) == 1);

    while (1) {
        mtx.lock();
        if (tid == ready_threads) {
            mtx.unlock();
            break;
        }
        mtx.unlock();
    }

    epfd = epoll_create1(0);

    if (epfd < 0) {
        fprintf(stderr, "Failed to create epoll\n");
        return;
    }

    for (unsigned int i = 0; i < t_nr_flows; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            fprintf(stderr, "Failed to create socket\n");
            perror("\n");
            return;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(t_server_port);
        server_addr.sin_addr.s_addr = server_ip_addr.s_addr;
        if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            fprintf(stderr, "Failed to connect to server\n");
            perror("connect");
            close(fd);
            return;
        }

        // close(fd);

        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
            fprintf(stderr, "Failed to set non-blocking\n");
            close(fd);
            return;
        }

        ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
        ev.data.ptr = new connection(fd, message_bytes, max_outstanding, short_response);

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            fprintf(stderr, "Failed to add fd to epoll\n");
            close(fd);
            close(epfd);
            return;
        }
        conn_fds_mtx.lock();
        conn_fds.push_back(fd);
        conn_fds_mtx.unlock();
    }

    printf("Connected to %s:%d successfully, total connections (%u) on Thread#%u\n", server_ip_str.c_str(), t_server_port, t_nr_flows, tid);
    
    mtx.lock();
    ready_threads++;
    mtx.unlock();
    
    while (ready_threads < nr_threads) {
        usleep(1000);
    }

    sleep(wait_seconds);

    while (1) {

        int nfds = epoll_wait(epfd, events, 128, -1);
        if (nfds) avg_nr_events.store((avg_nr_events.load() + nfds) / 2);
        for (int i = 0; i < nfds; i++) {
            c = (connection *)events[i].data.ptr;
            
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                fprintf(stderr, "EPOLLERR\n");
                conn_fds_mtx.lock();
                conn_fds.remove(c->fd);
                conn_fds_mtx.unlock();
                // remove from epoll
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
                close(c->fd);
                delete c;
                continue;
            }
            
            int ret = connection_events(tid, c, events[i].events);
            if (ret < 0) {
                conn_fds_mtx.lock();
                conn_fds.remove(c->fd);
                conn_fds_mtx.unlock();
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
                close(c->fd);
                delete c;
                continue;
            }
            if (ret == 0 && !c->no_epoll_out) {
                ev.events = EPOLLIN | EPOLLERR;
                ev.data.ptr = c;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
                    fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                c->no_epoll_out = 1;
            } else if (ret == 1 && c->no_epoll_out) {
                ev.events = EPOLLIN | EPOLLERR | EPOLLOUT;
                ev.data.ptr = c;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
                    fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                c->no_epoll_out = 0;
            }
        }
    }

    close(epfd);
    for (auto &fd : conn_fds) {
        close(fd);
    }
}

int parse_args(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "t:q:f:b:i:p:so:mw:l:")) != -1) {
        switch (opt) {
            case 'b':
                message_bytes = std::stoi(optarg);
                break;
            case 'i':
                server_ip_str = optarg;
                break;
            case 'f':
                nr_flows = std::stoi(optarg);
                break;
            case 't':
                nr_threads = std::stoi(optarg);
                break;
            case 'l':
                max_buf_size = std::stoi(optarg);
                break;
            case 'q':
                nr_queues = std::stoi(optarg);
                break;
            case 'p':
                server_port = std::stoi(optarg);
                break;
            case 'w':
                wait_seconds = std::stoi(optarg);
                break;
            case 'd':
                dump_io_stats = true;
                break;
            case 's':
                short_response = false;
                break;
            case 'm':
                multiport = true;
                break;
            case 'o':
                max_outstanding = std::stoi(optarg);
                break;
            default:
                std::cout << "Usage: " << argv[0] << 
                    " [-t nr_threads, default:1]" <<
                    " [-l max_buf_size, default:4096]" << 
                    " [-q nr_queues, default:1]" <<
                    " [-b bytes, default:128]" << 
                    " [-i server_ip, default:192.168.6.2]" <<
                    " [-f nr_flows, default:1]"
                    " [-p server_port, default:50000]" << 
                    " [-w wait_seconds, default:0]" <<
                    " [-s disable short_response, default:true]" << 
                    " [-o max_outstanding, default:1]" <<
                    " [-m enable multiport, default:false]" << 
                    " [-d dump_io_stats]" << std::endl;
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (parse_args(argc, argv))
    {
        std::cout << "Failed to parse arguments." << std::endl;
        exit(EXIT_FAILURE);
    }

    if (message_bytes > max_buf_size) {
        fprintf(stderr, "message_bytes larger than max_buf_size");
        return -1;
    }

    if (nr_threads == 0 || nr_threads > MAX_THREADS) {
        fprintf(stderr, "nr_threads must be between 1 and %d\n", MAX_THREADS);
        return -1;
    }


    for (unsigned int i = 0; i < nr_threads; i++) {
        threads.push_back(std::thread(thread_func, i));
    }

    std::thread([]() {
        while (1) {
            sleep(1);
            unsigned int _out = 0;
            unsigned int _in = 0;

            for (unsigned int i = 0; i < nr_threads; i++) {
                _out += total_req_bytes[i].load() - prev_total_req_bytes[i];
                _in += total_resp_bytes[i].load() - prev_total_resp_bytes[i];
                prev_total_req_bytes[i] = total_req_bytes[i].load();
                prev_total_resp_bytes[i] = total_resp_bytes[i].load();
            }
            total_out += _out;
            total_in += _in;

            size_t nr_conn_fds;
            {
                std::lock_guard<std::mutex> lock(conn_fds_mtx);
                nr_conn_fds = conn_fds.size();
            }

            printf("Throughput In/Out(%.2f/%.2f Gbps)(%.2f Kops) conn#(%lu), avg_nr_events(%u), total_out(%luB), total_in(%luB)\n", 
                _out * 8.0 / 1e9, _in * 8.0 / 1e9, _out / message_bytes / 1e3,
                nr_conn_fds, avg_nr_events.load(), total_out, total_in);
        }
    }).detach();

    for (auto &t : threads) {
        t.join();
    }

    return 0;
}
