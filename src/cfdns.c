/*  CFDNS
    Copyright (C) 2021 aa65535

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>

#include "config.h"

typedef struct {
  uint16_t id;
  uint16_t old_id;
  struct sockaddr *addr;
  socklen_t addrlen;
} id_addr_t;

typedef struct {
  struct in_addr net;
  in_addr_t mask;
} net_mask_t;

typedef struct {
  int entries;
  net_mask_t *nets;
} net_list_t;

// default max EDNS.0 UDP packet from RFC5625
#define BUF_SIZE 4096
static char global_buf[BUF_SIZE];
static int verbose = 0;

static const char *default_dns_servers = "8.8.8.8";
static char *dns_server = NULL;
static struct addrinfo *dns_server_addr;

static int parse_args(int argc, char **argv);

static int setnonblock(int sock);

static int resolve_dns_server();

static const char *default_listen_addr = "0.0.0.0";
static const char *default_listen_port = "53";

static char *listen_addr = NULL;
static char *listen_port = NULL;

static char *ip_file = NULL;
static char *ip_arg = NULL;
static struct in_addr better_ip;

static int parse_better_ip();

#define NETMASK_MIN 0
static char *cf_ips_file = NULL;
static net_list_t cf_ips_list;

static int parse_cf_ips();

static int test_ip_in_list(struct in_addr ip, const net_list_t *netlist);

static int dns_init_sockets();

static void dns_handle_local();

static void dns_handle_remote();

static int gen_resp_data(char *buf_ptr, struct in_addr *addr);

static const char *hostname_from_question(ns_msg msg);

static int should_replace_query(ns_msg msg);

static void queue_add(id_addr_t id_addr);

static id_addr_t *queue_lookup(uint16_t id);

#define ID_ADDR_QUEUE_LEN 128
// use a queue instead of hash here since it's not long
static id_addr_t id_addr_queue[ID_ADDR_QUEUE_LEN];
static int id_addr_queue_pos = 0;

static int local_sock;
static int remote_sock;

static void usage(void);

#define __LOG(o, t, v, s...) do {                                   \
  time_t now;                                                       \
  time(&now);                                                       \
  char *time_str = ctime(&now);                                     \
  time_str[strlen(time_str) - 1] = '\0';                            \
  if (t == 0) {                                                     \
    fprintf(o, "%s ", time_str);                                    \
    fprintf(o, s);                                                  \
    fflush(o);                                                      \
  } else if (t == 1) {                                              \
    fprintf(o, "%s %s:%d ", time_str, __FILE__, __LINE__);          \
    perror(v);                                                      \
  }                                                                 \
} while (0)

#define LOG(s...) __LOG(stdout, 0, "_", s)
#define ERR(s) __LOG(stderr, 1, s, "_")
#define VERR(s...) __LOG(stderr, 0, "_", s)

#ifdef DEBUG
#define DLOG(s...) LOG(s)
void __gcov_flush(void);
static void gcov_handler(int signum)
{
  __gcov_flush();
  exit(1);
}
#else
#define DLOG(s...)
#endif

#define BUF_PUT8(p, v) do {                                         \
  *p = v & 0xff;                                                    \
  p++;                                                              \
} while (0)

#define BUF_PUT16(p, v) do {                                        \
  BUF_PUT8(p, v >> 8);                                              \
  BUF_PUT8(p, v);                                                   \
} while (0)

#define BUF_SKIP(p, l) do {                                         \
  p+=l;                                                             \
} while (0)

#define MEM_CPY(d, s, l) do {                                       \
  memcpy(d, s, l);                                                  \
  d+=l;                                                             \
} while (0)

int main(int argc, char **argv) {
  fd_set readset, errorset;
  int max_fd, retval;

#ifdef DEBUG
  signal(SIGTERM, gcov_handler);
#endif

  memset(&id_addr_queue, 0, sizeof(id_addr_queue));
  if (0 != parse_args(argc, argv))
    return EXIT_FAILURE;
  if (0 != parse_better_ip())
    return EXIT_FAILURE;
  if (0 != parse_cf_ips())
    return EXIT_FAILURE;
  if (0 != resolve_dns_server())
    return EXIT_FAILURE;
  if (0 != dns_init_sockets())
    return EXIT_FAILURE;

  max_fd = MAX(local_sock, remote_sock) + 1;
  while (1) {
    FD_ZERO(&readset);
    FD_ZERO(&errorset);
    FD_SET(local_sock, &readset);
    FD_SET(local_sock, &errorset);
    FD_SET(remote_sock, &readset);
    FD_SET(remote_sock, &errorset);
    struct timeval timeout = {
      .tv_sec = 0,
      .tv_usec = 50 * 1000,
    };
    retval = select(max_fd, &readset, NULL, &errorset, &timeout);
    if (-1 == retval) {
      ERR("select");
      return EXIT_FAILURE;
    }
    if (0 == retval) {
      continue;
    }
    if (FD_ISSET(local_sock, &errorset)) {
      VERR("local_sock error\n");
      return EXIT_FAILURE;
    }
    if (FD_ISSET(remote_sock, &errorset)) {
      VERR("remote_sock error\n");
      return EXIT_FAILURE;
    }
    if (FD_ISSET(local_sock, &readset))
      dns_handle_local();
    if (FD_ISSET(remote_sock, &readset))
      dns_handle_remote();
  }
  return EXIT_SUCCESS;
}

static int setnonblock(int sock) {
  int flags;
  flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    ERR("fcntl");
    return -1;
  }
  if (-1 == fcntl(sock, F_SETFL, flags | O_NONBLOCK)) {
    ERR("fcntl");
    return -1;
  }
  return 0;
}

static int parse_args(int argc, char **argv) {
  int ch;
  while ((ch = getopt(argc, argv, "hb:p:s:l:i:c:vV")) != -1) {
    switch (ch) {
      case 'h':
        usage();
        exit(0);
      case 'b':
        listen_addr = strdup(optarg);
        break;
      case 'p':
        listen_port = strdup(optarg);
        break;
      case 's':
        dns_server = strdup(optarg);
        break;
      case 'l':
        ip_file = strdup(optarg);
        break;
      case 'i':
        ip_arg = strdup(optarg);
        break;
      case 'c':
        cf_ips_file = strdup(optarg);
        break;
      case 'v':
        verbose = 1;
        break;
      case 'V':
        printf("CFDNS %s\n", PACKAGE_VERSION);
        exit(0);
      default:
        usage();
        exit(1);
    }
  }
  if (dns_server == NULL) {
    dns_server = strdup(default_dns_servers);
  }
  if (listen_addr == NULL) {
    listen_addr = strdup(default_listen_addr);
  }
  if (listen_port == NULL) {
    listen_port = strdup(default_listen_port);
  }
  argc -= optind;
  argv += optind;
  return 0;
}

static int resolve_dns_server() {
  struct addrinfo hints;
  int r;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  char *port;
  if ((port = (strrchr(dns_server, '#'))) ||
      (port = (strrchr(dns_server, ':')))) {
    *port = '\0';
    port++;
  } else {
    port = "53";
  }
  if (0 != (r = getaddrinfo(dns_server, port, &hints, &dns_server_addr))) {
    VERR("%s:%s\n", gai_strerror(r), dns_server);
    return -1;
  }
  return 0;
}

static int parse_better_ip() {
  FILE *fp;
  char line_buf[32];
  char *line = NULL;
  size_t len = sizeof(line_buf);
  int i = 0;

  if (ip_arg != NULL) {
    if (0 != inet_aton(ip_arg, &better_ip)) {
        if (verbose)
          LOG("better ip: %s\n", ip_arg);
      return 0;
    }
  }

  if (ip_file == NULL) {
    VERR("ip list file is not specified\n");
    return -1;
  }

  fp = fopen(ip_file, "rb");
  if (fp == NULL) {
    ERR("fopen");
    VERR("Can't open ip list: %s\n", ip_file);
    return -1;
  }

  while ((line = fgets(line_buf, len, fp))) {
    char *sp_pos;
    sp_pos = strchr(line, '\r');
    if (sp_pos) *sp_pos = 0;
    sp_pos = strchr(line, '\n');
    if (sp_pos) *sp_pos = 0;
    sp_pos = strchr(line, '/');
    if (sp_pos) *sp_pos = 0;
    if (0 != inet_aton(line, &better_ip)) {
      if (verbose)
        LOG("better ip: %s\n", line);
      return 0;
    }
  }

  VERR("invalid ip list file: %s\n", ip_file);
  return -1;
}

static int cmp_net_mask(const void *a, const void *b) {
  net_mask_t *neta = (net_mask_t *) a;
  net_mask_t *netb = (net_mask_t *) b;
  if (neta->net.s_addr == netb->net.s_addr)
    return 0;
  if (ntohl(neta->net.s_addr) > ntohl(netb->net.s_addr))
    return 1;
  return -1;
}

static int parse_cf_ips() {
  FILE *fp;
  char line_buf[32];
  char *line;
  size_t len = sizeof(line_buf);
  char net[32];
  cf_ips_list.entries = 0;
  int i = 0;
  int cidr;

  if (cf_ips_file == NULL) {
    VERR("cf ips file is not specified\n");
    return -1;
  }

  fp = fopen(cf_ips_file, "rb");
  if (fp == NULL) {
    ERR("fopen");
    VERR("Can't open cf ips file: %s\n", cf_ips_file);
    return -1;
  }

  while ((line = fgets(line_buf, len, fp))) {
    cf_ips_list.entries++;
  }

  cf_ips_list.nets = calloc(cf_ips_list.entries, sizeof(net_mask_t));
  if (0 != fseek(fp, 0, SEEK_SET)) {
    VERR("fseek");
    return -1;
  }

  while ((line = fgets(line_buf, len, fp))) {
    char *sp_pos;
    sp_pos = strchr(line, '\r');
    if (sp_pos) *sp_pos = 0;
    sp_pos = strchr(line, '\n');
    if (sp_pos) *sp_pos = 0;
    if (verbose)
      LOG("cloudflare ip: %s\n", line);
    sp_pos = strchr(line, '/');
    if (sp_pos) {
      *sp_pos = 0;
      cidr = atoi(sp_pos + 1);
      if (cidr > 0) {
        cf_ips_list.nets[i].mask = (1 << (32 - cidr)) - 1;
      } else {
        cf_ips_list.nets[i].mask = UINT32_MAX;
      }
    } else {
      cf_ips_list.nets[i].mask = NETMASK_MIN;
    }
    if (0 == inet_aton(line, &cf_ips_list.nets[i].net)) {
      VERR("invalid addr %s in %s:%d\n", line, cf_ips_file, i + 1);
      return 1;
    }
    i++;
  }

  qsort(cf_ips_list.nets, cf_ips_list.entries, sizeof(net_mask_t), cmp_net_mask);

  fclose(fp);
  return 0;
}

static int test_ip_in_list(struct in_addr ip, const net_list_t *netlist) {
  // binary search
  int l = 0, r = netlist->entries - 1;
  int m, cmp;
  if (netlist->entries == 0)
    return 0;
  net_mask_t ip_net;
  ip_net.net = ip;
  while (l <= r) {
    m = (l + r) >> 1;
    cmp = cmp_net_mask(&netlist->nets[m], &ip_net);
    if (cmp < 0)
      l = m + 1;
    else if (cmp > 0)
      r = m - 1;
    else
      return 1;
#ifdef DEBUG
    DLOG("l=%d, r=%d\n", l, r);
    DLOG("%s, %d\n", inet_ntoa(netlist->nets[m].net), netlist->nets[m].mask);
#endif
  }
#ifdef DEBUG
  DLOG("nets: %x <-> %x\n", ntohl(netlist->nets[l - 1].net.s_addr, ntohl(ip.s_addr));
  DLOG("mask: %x\n", netlist->nets[l - 1].mask);
#endif
  if (0 == l || (ntohl(ip.s_addr) > (ntohl(netlist->nets[l - 1].net.s_addr) | netlist->nets[l - 1].mask))) {
    return 0;
  }
  return 1;
}

static int dns_init_sockets() {
  struct addrinfo hints;
  struct addrinfo *addr_ip;
  int r;

  local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (0 != setnonblock(local_sock))
    return -1;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (0 != (r = getaddrinfo(listen_addr, listen_port, &hints, &addr_ip))) {
    VERR("%s:%s:%s\n", gai_strerror(r), listen_addr, listen_port);
    return -1;
  }
  if (0 != bind(local_sock, addr_ip->ai_addr, addr_ip->ai_addrlen)) {
    ERR("bind");
    VERR("Can't bind address %s:%s\n", listen_addr, listen_port);
    return -1;
  }
  freeaddrinfo(addr_ip);
  remote_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (0 != setnonblock(remote_sock))
    return -1;
  return 0;
}

static void dns_handle_local() {
  struct sockaddr *src_addr = malloc(sizeof(struct sockaddr));
  socklen_t src_addrlen = sizeof(struct sockaddr);
  uint16_t query_id;
  ssize_t len;
  int i;
  int ended = 0;
  const char *question_hostname;
  ns_msg msg;
  len = recvfrom(local_sock, global_buf, BUF_SIZE, 0, src_addr, &src_addrlen);
  if (len > 0) {
    if (ns_initparse((const u_char *) global_buf, len, &msg) < 0) {
      ERR("ns_initparse");
      free(src_addr);
      return;
    }

    if (verbose) {
      question_hostname = hostname_from_question(msg);
      if (question_hostname)
        LOG("request %s from %s:%d", question_hostname, inet_ntoa(((struct sockaddr_in *) src_addr)->sin_addr), htons(((struct sockaddr_in *) src_addr)->sin_port));
    }

    // parse DNS query id
    query_id = ns_msg_id(msg);
    // assign a new id
    uint16_t new_id;
    do {
      struct timeval tv;
      gettimeofday(&tv, 0);
      int randombits = (tv.tv_sec << 8) ^tv.tv_usec;
      new_id = randombits & 0xffff;
    } while (queue_lookup(new_id));

    uint16_t ns_new_id = htons(new_id);
    memcpy(global_buf, &ns_new_id, 2);

    id_addr_t id_addr;
    id_addr.id = new_id;
    id_addr.old_id = query_id;
    id_addr.addr = src_addr;
    id_addr.addrlen = src_addrlen;
    queue_add(id_addr);

    if (-1 == sendto(remote_sock, global_buf, len, 0, dns_server_addr->ai_addr, dns_server_addr->ai_addrlen))
      ERR("sendto");

    if (verbose)
      printf("\n");
  } else
    ERR("recvfrom");
}

static void dns_handle_remote() {
  struct sockaddr *src_addr = malloc(sizeof(struct sockaddr));
  socklen_t src_len = sizeof(struct sockaddr);
  uint16_t query_id;
  ssize_t len;
  const char *question_hostname;
  int r;
  ns_msg msg;
  len = recvfrom(remote_sock, global_buf, BUF_SIZE, 0, src_addr, &src_len);
  if (len > 0) {
    if (ns_initparse((const u_char *) global_buf, len, &msg) < 0) {
      ERR("ns_initparse");
      free(src_addr);
      return;
    }

    if (verbose) {
      question_hostname = hostname_from_question(msg);
      if (question_hostname)
        LOG("response %s from %s:%d - ", question_hostname, inet_ntoa(((struct sockaddr_in *) src_addr)->sin_addr), htons(((struct sockaddr_in *) src_addr)->sin_port));
    }

    // parse DNS query id
    query_id = ns_msg_id(msg);
    id_addr_t *id_addr = queue_lookup(query_id);
    if (id_addr) {
      id_addr->addr->sa_family = AF_INET;
      uint16_t ns_old_id = htons(id_addr->old_id);
      memcpy(global_buf, &ns_old_id, 2);
      r = should_replace_query(msg);
      if (r == 0) {
        if (verbose)
          printf("pass\n");
      } else {
        if (verbose)
          printf("replace\n");
        len = gen_resp_data(global_buf, &better_ip);
      }
      if (-1 == sendto(local_sock, global_buf, len, 0, id_addr->addr, id_addr->addrlen))
        ERR("sendto");
    } else {
      if (verbose)
        printf("skip\n");
    }
    free(src_addr);
  } else
    ERR("recvfrom");
}

static int gen_resp_data(char *buf_ptr, struct in_addr *addr) {
  u_int i, len;
  uint16_t count;
  char *buf_start = buf_ptr;
  // Skip Transaction ID & Flags & Questions
  BUF_SKIP(buf_ptr, 6);
  // Set Answer RRs: 1
  BUF_PUT16(buf_ptr, 1);
  // Set Authority RRs: 0
  BUF_PUT16(buf_ptr, 0);
  // Set Additional RRs: 0
  BUF_PUT16(buf_ptr, 0);
  // Skip Queries
  count = ns_get16(buf_start + 4);
  for (i = 0; i < count; i++) {
    len = strlen(buf_ptr) + 5;
    BUF_SKIP(buf_ptr, len);
  }
  // Set Answers Data
  BUF_PUT16(buf_ptr, 0xc00c);  // Name
  BUF_PUT16(buf_ptr, 1); // Type
  BUF_PUT16(buf_ptr, 1); // Class
  BUF_PUT16(buf_ptr, 0); // TTL
  BUF_PUT16(buf_ptr, 300); // TTL
  BUF_PUT16(buf_ptr, 4); // Data Length
  MEM_CPY(buf_ptr, addr, 4); // Data
  return buf_ptr - buf_start;
}

static void queue_add(id_addr_t id_addr) {
  id_addr_queue_pos = (id_addr_queue_pos + 1) % ID_ADDR_QUEUE_LEN;
  // free next hole
  id_addr_t old_id_addr = id_addr_queue[id_addr_queue_pos];
  free(old_id_addr.addr);
  id_addr_queue[id_addr_queue_pos] = id_addr;
}

static id_addr_t *queue_lookup(uint16_t id) {
  int i;
  for (i = 0; i < ID_ADDR_QUEUE_LEN; i++) {
    if (id_addr_queue[i].id == id)
      return id_addr_queue + i;
  }
  return NULL;
}

static char *hostname_buf = NULL;
static size_t hostname_buflen = 0;

static const char *hostname_from_question(ns_msg msg) {
  ns_rr rr;
  int rrnum, rrmax;
  const char *result;
  int result_len;
  rrmax = ns_msg_count(msg, ns_s_qd);
  if (rrmax == 0)
    return NULL;
  for (rrnum = 0; rrnum < rrmax; rrnum++) {
    if (ns_parserr(&msg, ns_s_qd, rrnum, &rr)) {
      ERR("ns_parserr");
      return NULL;
    }
    result = ns_rr_name(rr);
    result_len = strlen(result) + 1;
    if (result_len > hostname_buflen) {
      hostname_buflen = result_len << 1;
      hostname_buf = realloc(hostname_buf, hostname_buflen);
    }
    memcpy(hostname_buf, result, result_len);
    return hostname_buf;
  }
  return NULL;
}

static int should_replace_query(ns_msg msg) {
  ns_rr rr;
  int rrnum, rrmax;
  int ns_t_a_num = 0;
  void *r;
  rrmax = ns_msg_count(msg, ns_s_an);
  for (rrnum = 0; rrnum < rrmax; rrnum++) {
    if (ns_parserr(&msg, ns_s_an, rrnum, &rr)) {
      ERR("ns_parserr");
      return 0;
    }
    u_int type;
    type = ns_rr_type(rr);
    if (type == ns_t_a) {
      ns_t_a_num++;
      const u_char *rd;
      rd = ns_rr_rdata(rr);
      if (verbose)
        printf("%s, ", inet_ntoa(*(struct in_addr *) rd));
      if (test_ip_in_list(*(struct in_addr *) rd, &cf_ips_list)) {
        // replace
        return 1;
      }
    }
  }
  return 0;
}

static void usage() {
  printf("%s\n", "\
usage: cfdns [-h] [-l IPLIST_FILE] [-b BIND_ADDR] [-p BIND_PORT]\n\
       [-c CF_IPS_FILE] [-i BETTER_IP] [-s DNS] [-v] [-V]\n\
Forward DNS requests.\n\
\n\
  -c CF_IPS_FILE        path to cloudflare ips file\n\
  -l IPLIST_FILE        path to better ip file\n\
  -i BETTER_IP          better ip, if specified, the -l parameter is ignored \n\
  -b BIND_ADDR          address that listens, default: 0.0.0.0\n\
  -p BIND_PORT          port that listens, default: 53\n\
  -s DNS                DNS servers to use, default: 8.8.8.8\n\
  -v                    verbose logging\n\
  -h                    show this help message and exit\n\
  -V                    print version and exit\n\
\n");
}
