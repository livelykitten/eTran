#pragma once

#include <app_if.h>
#include <xsk_if.h>
#include <tcp_if.h>
#include <homa_if.h>
#include <intf/intf.h>

#include "eTran_common.h"

#define MAX_FD 1024 * 1024

#define CONN_AFFINITY

#define BATCH_IO_THRESHOLD 16384 // bytes

// socket.cc
extern int eTran_socket(int domain, int type, int protocol);
extern int eTran_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int eTran_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int eTran_listen(int sockfd, int backlog);
extern int eTran_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int eTran_close(int sockfd);
extern ssize_t eTran_read(int fd, void *buf, size_t count);
extern ssize_t eTran_write(int fd, const void *buf, size_t count);
extern int eTran_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
extern int eTran_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
extern int eTran_fcntl(int fd, int cmd, int flags);
extern int eTran_epoll_create1(int flags);
extern int eTran_epoll_ctl(int epfd, int op, int fd,
    struct epoll_event *event);
extern int eTran_epoll_wait(int epfd, struct epoll_event *events,
    int maxevents, int timeout);
extern int eTran_select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout);

// TCP Control path API
int eTran_tcp_poll_events(struct app_ctx_per_thread *tctx, struct eTrantcp_event *events, int maxevents, int timeout);
int eTran_tcp_open(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, int fd, uint32_t remote_ip, uint16_t remote_port);
int eTran_tcp_bind(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, int fd, uint32_t local_ip, uint32_t local_port, bool reuseport);
int eTran_tcp_listen(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, struct eTrantcp_listener *listener, int fd, uint16_t port, uint32_t backlog);
int eTran_tcp_accept(struct app_ctx_per_thread *tctx, struct eTrantcp_listener *listener, struct eTrantcp_connection *conn, int fd, int newfd);
int eTran_tcp_close(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, int fd);

// Homa Control path API
int eTran_homa_poll_events(struct app_ctx_per_thread *tctx, struct eTranhoma_event *events, int maxevents, int timeout);
int eTran_homa_bind(struct app_ctx_per_thread *tctx, struct eTranhoma_socket *socket, int fd, uint32_t local_ip, uint32_t local_port);
int eTran_homa_close(struct app_ctx_per_thread *tctx, struct eTranhoma_socket *socket, int fd);

void tcp_flow_tx_segmentation_zc(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, const void *buf, size_t len);
size_t tcp_flow_tx_segmentation_zc_retransmission(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, size_t len);

static inline void dma(void *dst, void *src, size_t len)
{
    memcpy(dst, src, len);
}

static inline size_t eTran_tcp_rx_contiguous_count(struct eTrantcp_connection *conn)
{
    size_t contiguous = 0;

    while (contiguous < conn->rx_buf_size) {
        uint32_t expected_pos = conn->rxb_head + contiguous;
        if (expected_pos >= conn->rx_buf_size) {
            expected_pos -= conn->rx_buf_size;
        }

        size_t best_len = 0;
        for (auto it = conn->rx_addrs.begin(); it != conn->rx_addrs.end(); it++) {
            auto [addr, pkt] = *it;
            (void)addr;
            uint16_t py_len = rxmeta_plen(pkt);
            uint32_t rx_pos = rxmeta_pos(pkt);
            uint32_t delta = expected_pos >= rx_pos ?
                             expected_pos - rx_pos :
                             conn->rx_buf_size - rx_pos + expected_pos;

            if (delta < py_len) {
                best_len = py_len - delta;
                break;
            }
        }

        if (!best_len) {
            break;
        }

        contiguous += best_len;
    }

    return contiguous;
}

/**
 * @brief return how many bytes can be submitted to AF_XDP
 */
static inline unsigned int xsk_bytes_avail(struct eTrantcp_connection *conn)
{
    return conn->xsk_budget > conn->txb_sent ? conn->xsk_budget - conn->txb_sent : 0;
}

/**
 * @brief return how many available bytes in the transmit buffer
 */
static inline size_t txb_bytes_avail(struct eTrantcp_connection *conn)
{
    return std::min(conn->tx_buf_size - conn->txb_sent - conn->txb_allocated, xsk_bytes_avail(conn));
}

/**
 * @brief submit data in the connection's tx buffer to AF_XDP for segmentation and transmission
 * @param tctx the per-thread context
 * @param conn the connection
 * @param buf the data to be submitted
 * @param len the length of data to be submitted
 * @return 0 on success, -EINVAL on failure
 */
static inline int eTran_tcp_tx_submit_zc(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, const void *buf, size_t len)
{
    if (unlikely(conn->status != CONN_OPEN))
    {
        fprintf(stderr, "eTran_tcp_tx_submit_zc(): conn->status != CONN_OPEN\n");
        return -EINVAL;
    }

    if (unlikely(conn->txb_allocated < len))
    {
        fprintf(stderr, "eTran_tcp_tx_submit_zc(): (%p), txb_allocated(%u) < len(%lu)\n", conn, conn->txb_allocated, len);
        return -EINVAL;
    }

    tcp_flow_tx_segmentation_zc(tctx, conn, buf, len);

    conn->txb_allocated -= len;
    conn->txb_sent += len;

    return 0;
}

static inline int eTran_tcp_tx_submit_zc_retransmission(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, size_t len)
{
    if (unlikely(conn->status != CONN_OPEN))
    {
        fprintf(stderr, "eTran_tcp_tx_submit_zc_retransmission(): conn->status != CONN_OPEN\n");
        return -EINVAL;
    }

    len = tcp_flow_tx_segmentation_zc_retransmission(tctx, conn, len);

    conn->txb_allocated -= len;
    conn->txb_sent += len;

    return 0;
}

static inline ssize_t eTran_tcp_rx_peek_count_zc(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, size_t count, void *buf)
{
    uint32_t copy_offset = 0;
    if (conn->rxb_used == 0) {
        return 0;
    }

    if (count > conn->rxb_used) {
        count = conn->rxb_used;
    }

    while (copy_offset < count) {
        uint32_t expected_pos = conn->rxb_head + copy_offset;
        if (expected_pos >= conn->rx_buf_size) {
            expected_pos -= conn->rx_buf_size;
        }

        auto it = conn->rx_addrs.begin();
        uint32_t pkt_delta = 0;
        for (; it != conn->rx_addrs.end(); it++) {
            auto [addr, pkt] = *it;
            uint16_t py_len = rxmeta_plen(pkt);
            uint32_t rx_pos = rxmeta_pos(pkt);
            uint32_t delta = expected_pos >= rx_pos ?
                             expected_pos - rx_pos :
                             conn->rx_buf_size - rx_pos + expected_pos;
            if (delta < py_len) {
                pkt_delta = delta;
                break;
            }
        }

        if (it == conn->rx_addrs.end()) {
            if (copy_offset == 0) {
                uint32_t first_pos = POISON_32;
                uint16_t first_len = POISON_16;
                uint16_t first_off = POISON_16;
                if (!conn->rx_addrs.empty()) {
                    auto [first_addr, first_pkt] = conn->rx_addrs.front();
                    (void)first_addr;
                    first_pos = rxmeta_pos(first_pkt);
                    first_len = rxmeta_plen(first_pkt);
                    first_off = rxmeta_poff(first_pkt);
                }
                fprintf(stderr,
                        "rx ordered peek stalled: expected_pos=%u rxb_head=%u rxb_used=%u "
                        "count=%zu rx_addrs=%zu first_pos=%u first_len=%u first_off=%u\n",
                        expected_pos, conn->rxb_head, conn->rxb_used, count,
                        conn->rx_addrs.size(), first_pos, first_len, first_off);
            }
            break;
        }

        auto [addr, pkt] = *it;
        uint16_t py_len = rxmeta_plen(pkt);
        uint16_t py_off = rxmeta_poff(pkt);
        auto append_len = std::min((size_t)py_len - pkt_delta, count - copy_offset);

        dma((uint8_t *)buf + copy_offset, pkt + py_off + pkt_delta, append_len);
        copy_offset += append_len;

        if (likely(pkt_delta + append_len == py_len)) {
            thread_bcache_prod(&tctx->iobuffer, addr);
            conn->rx_addrs.erase(it);
        } else {
            uint32_t rx_pos = expected_pos + append_len;
            if (rx_pos >= conn->rx_buf_size) {
                rx_pos -= conn->rx_buf_size;
            }
            rxmeta_set_poff(pkt, py_off + pkt_delta + append_len);
            rxmeta_set_plen(pkt, py_len - pkt_delta - append_len);
            rxmeta_set_pos(pkt, rx_pos);
            break;
        }
    }

    return copy_offset;
}

/**
 * @brief Release len bytes data from the connection
 * @param tctx the per-thread context
 * @param conn the connection
 * @param len the length of data to be released
 * @return 0 on success, -EINVAL on failure
 */
static inline int eTran_tcp_rx_release(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, size_t len)
{
    if (conn->rxb_used < len)
    {
        fprintf(stderr, "eTran_tcp_submit_rx(): conn->rxb_used < len\n");
        return -EINVAL;
    }

    conn->rxb_used -= len;
    conn->rxb_bump += len;

    conn->rxb_head += len;
    if (conn->rxb_head >= conn->rx_buf_size) {
        conn->rxb_head -= conn->rx_buf_size;
    }

    if (unlikely((conn->rxb_bump > std::min(std::min(conn->rx_buf_size >> 2, ((unsigned int)0xFFFF) << TCP_WND_SCALE), (unsigned int)32768) || conn->force_rx_bump) 
        && !conn->in_rx_bump_pending))
    {
        tctx->rx_bump_pending_conns.push_back(conn);
        conn->in_rx_bump_pending = true;
    }

    conn->force_rx_bump = false;

    return 0;
}

/**
 * @brief get the amount of data that can be transmitted in the connection's tx buffer
 */
static inline ssize_t eTran_tcp_tx_avail(struct eTrantcp_connection *conn)
{
    return txb_bytes_avail(conn);
}

/**
 * @brief reserve space in the connection's tx buffer for data transmission
 * @param tctx the per-thread context
 * @param conn the connection
 * @param reserve_len the length of data to be reserved
 * @return the length of data reserved on success, -EINVAL on failure
 */
static inline ssize_t eTran_tcp_tx_reserve_zc(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, size_t reserve_len)
{
    uint32_t avail;
    uint32_t head;

    if (unlikely(conn->status != CONN_OPEN))
    {
        fprintf(stderr, "eTran_tcp_tx_reserve_zc(): conn->status != CONN_OPEN\n");
        return -EINVAL;
    }

    avail = txb_bytes_avail(conn);
    if (avail < reserve_len)
    {
        reserve_len = avail;
    }

    // get current head of tx buffer
    head = conn->txb_head + conn->txb_allocated;

    if (head >= conn->tx_buf_size)
    {
        head -= conn->tx_buf_size;
    }

    conn->txb_allocated += reserve_len;

    return reserve_len;
}

static inline int notify_kernel_tcp_conn_open(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, int fd,
                                          uint32_t remote_ip, uint16_t remote_port)
{
    lrpc_msg msg;
    struct appout_tcp_open_t *open_msg = (struct appout_tcp_open_t *)msg.data;

    msg.cmd = APPOUT_TCP_OPEN;
    open_msg->opaque_connection = OPAQUE(conn);
    open_msg->fd = fd;
    open_msg->remote_ip = remote_ip;
    open_msg->remote_port = remote_port;

    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_tcp_conn_open(): lrpc_send() failed\n");
        return -1;
    }
    return 0;
}

static inline int notify_kernel_tcp_conn_bind(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, int fd,
                                          uint32_t local_ip, uint16_t local_port, bool reuseport)
{
    lrpc_msg msg;
    struct appout_tcp_bind_t *bind_msg = (struct appout_tcp_bind_t *)msg.data;

    msg.cmd = APPOUT_TCP_BIND;
    bind_msg->opaque_connection = OPAQUE(conn);
    bind_msg->fd = fd;
    bind_msg->local_ip = local_ip;
    bind_msg->local_port = local_port;
    bind_msg->reuseport = reuseport;

    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_tcp_conn_bind(): lrpc_send() failed\n");
        return -1;
    }

    return 0;
}

static inline int notify_kernel_tcp_conn_listen(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, struct eTrantcp_listener *listener, int fd, unsigned int backlog)
{
    lrpc_msg msg;
    struct appout_tcp_listen_t *listen_msg = (struct appout_tcp_listen_t *)msg.data;

    msg.cmd = APPOUT_TCP_LISTEN;

    listen_msg->opaque_listener = OPAQUE(listener);
    listen_msg->opaque_connection = OPAQUE(conn);
    listen_msg->fd = fd;
    listen_msg->backlog = backlog;

    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_tcp_conn_listen(): lrpc_send() failed\n");
        return -1;
    }

    return 0;
}

static inline int notify_kernel_tcp_conn_accept(struct app_ctx_per_thread *tctx, struct eTrantcp_listener *listener,
                                            struct eTrantcp_connection *conn, int fd, int newfd, uint16_t local_port)
{
    lrpc_msg msg;
    struct appout_tcp_accept_t *accept_msg = (struct appout_tcp_accept_t *)msg.data;

    msg.cmd = APPOUT_TCP_ACCEPT;

    accept_msg->tid = tctx->tid;
    accept_msg->opaque_connection = OPAQUE(conn);
    accept_msg->opaque_listener = OPAQUE(listener);
    accept_msg->fd = fd;
    accept_msg->newfd = newfd;
    accept_msg->local_port = local_port;

    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_tcp_conn_accept(): lrpc_send() failed\n");
        return -1;
    }

    return 0;
}

static inline int notify_kernel_tcp_conn_close(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, int fd)
{
    lrpc_msg msg;
    struct appout_tcp_close_t *close_msg = (struct appout_tcp_close_t *)msg.data;
    
    msg.cmd = APPOUT_TCP_CLOSE;
    
    close_msg->opaque_connection = OPAQUE(conn);
    close_msg->fd = fd;
    close_msg->local_ip = conn->local_ip;
    close_msg->remote_ip = conn->remote_ip;
    close_msg->local_port = conn->local_port;
    close_msg->remote_port = conn->remote_port;

    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_tcp_conn_close(): lrpc_send() failed\n");
        return -1;
    }

    return 0;
}

static inline ssize_t conn_recv(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, void *buf, size_t count)
{
    ssize_t ret;

    ret = eTran_tcp_rx_peek_count_zc(tctx, conn, count, buf);

    if (ret <= 0)
        return ret;

    eTran_tcp_rx_release(tctx, conn, ret);

    return ret;
}

static inline ssize_t conn_send(struct app_ctx_per_thread *tctx, struct eTrantcp_connection *conn, const void *buf, size_t count)
{
    ssize_t ret;

    ret = eTran_tcp_tx_reserve_zc(tctx, conn, count);

    if (ret <= 0)
        return ret;    

    eTran_tcp_tx_submit_zc(tctx, conn, buf, ret);

    return ret;
}

static inline int notify_kernel_homa_bind(struct app_ctx_per_thread *tctx, struct eTranhoma_socket *socket, int fd)
{
    lrpc_msg msg;
    struct appout_homa_bind_t *bind_msg = (struct appout_homa_bind_t *)msg.data;
    
    uint32_t local_ip = socket->local_ip;
    uint16_t local_port = socket->local_port;

    msg.cmd = APPOUT_HOMA_BIND;
    bind_msg->opaque_socket = OPAQUE(socket);
    bind_msg->fd = fd;
    bind_msg->local_ip = local_ip;
    bind_msg->local_port = local_port;

    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_homa_bind(): lrpc_send() failed\n");
        return -1;
    }
    return 0;
}

static inline int notify_kernel_homa_close(struct app_ctx_per_thread *tctx, struct eTranhoma_socket *socket, int fd)
{
    lrpc_msg msg;
    struct appout_homa_close_t *close_msg = (struct appout_homa_close_t *)msg.data;

    msg.cmd = APPOUT_HOMA_CLOSE;
    close_msg->opaque_socket = OPAQUE(socket);
    close_msg->fd = fd;
    if (lrpc_send(&tctx->app_out, &msg))
    {
        fprintf(stderr, "notify_kernel_homa_close(): lrpc_send() failed\n");
        return -1;
    }

    return 0;
}
