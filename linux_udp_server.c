#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "linux_udp.h"


int udp_creat_server(const struct sockaddr_in *address)
{
    int server_fd = -1;
    
    /*设置UDP的接收和发送缓冲*/
    int	send_buf_size = 2*MAX_MSG_LENGTH;
    int recv_buf_size = 2*MAX_MSG_LENGTH;
    if(address)
    {
        DEBUG_LOG("Make server on address %u.%u.%u.%u:%u",
                  YGETBYTE(address->sin_addr.s_addr, 0),
                  YGETBYTE(address->sin_addr.s_addr, 1),
                  YGETBYTE(address->sin_addr.s_addr, 2),
                  YGETBYTE(address->sin_addr.s_addr, 3),
                  ntohs(address->sin_port));
    }

    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (0 > server_fd)
    {
        perror( "Couldn't create socket!!!\n");
        DEBUG_LOG("socket error");
    }
    else
    {
        /*重新设置套接字的接收和发送缓冲大小*/
        if (INVALID_SOCKET == setsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, 
                                         (const void *)&send_buf_size,sizeof(int)) )
        {
            perror( "setsockopt  SO_SNDBUF  failed\n");
            DEBUG_LOG("setsockopt error");
            close(server_fd);
            server_fd = INVALID_SOCKET;
            return server_fd; 
        }   

        if (INVALID_SOCKET == setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, 
                                         (const void *)&recv_buf_size,sizeof(int)))
        {
            perror( "setsockopt  SO_RCVBUF  failed\n");
            DEBUG_LOG("setsockopt error");
            close(server_fd);
            server_fd = INVALID_SOCKET;
            return server_fd; 
        }
        if(address)
        {
            if (INVALID_SOCKET == bind(server_fd, (struct sockaddr *)address, sizeof(*address)))
            {
                perror( "Can't bind socket\n");
                DEBUG_LOG( "setsockopt error");
                close(server_fd);
                server_fd = INVALID_SOCKET;
            }
        }
    }
    
    return server_fd;
}


int udp_epoll_creat(void){

    int efd = epoll_create(1);
    if (efd == -1) {
        perror("epoll_create");
        DEBUG_LOG( "udp epoll creat error");
        exit(EXIT_FAILURE);
    }

    return efd;
}

void udp_epoll_add(int efd, int sfd){

    struct epoll_event ev;
    
    ev.events  = EPOLLIN;
    ev.data.fd = sfd;
    
    if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &ev) == -1) {
        perror("epoll_ctl: listen_sock");
        DEBUG_LOG( "udp epoll add error");
        exit(EXIT_FAILURE);
    }
}

static inline void  udp_recvfrom(int rfd, udp_process_t *udp_process)
{
    char buf[MAX_MTU_LEN];
    int  bytes_recv;
    
    struct sockaddr_in client_addr;
    socklen_t         cliaddr_len;
    
	//char str[INET_ADDRSTRLEN];

    bytes_recv = recvfrom( rfd, buf, MAX_MTU_LEN, 0, 
                           (struct sockaddr *)&client_addr,
                           (socklen_t *)&cliaddr_len);
     if (bytes_recv == -1 )
     {
          perror("recvfrom");
          DEBUG_LOG( "recvfrom error");
          exit(EXIT_FAILURE);
     }
     
     //DEBUG_LOG("coreid[%d] receive[%d] from %s at PORT %d\n", 
     //          udp_process->core_id, rfd, 
     //          inet_ntop(AF_INET, &client_addr.sin_addr, str, sizeof(str)),
     //          ntohs(client_addr.sin_port));

     udp_process->recv_calls += 1;
     udp_process->recv_bytes += bytes_recv;
     
     //DEBUG_LOG("recv calls(%d),bytes(%d)",udp_process->calls,udp_process->bytes);
}


void udp_epoll_loop(void *threadData) {

    int i, nfds;

    uint32_t events;
    
    struct epoll_event epoll_events[MAX_EVENT];
    
    udp_process_t *udp_process = (udp_process_t*)threadData;
    
    int epoll_fd = udp_process->epfd;

    if(!epoll_fd)
    {
        DEBUG_LOG( "threadData error");
        exit(EXIT_FAILURE);
    }
    
    while(1) {
    
        nfds = epoll_wait(epoll_fd, epoll_events, MAX_EVENT, -1);
        if(nfds == -1)
        {
            if(errno == EINTR)
                continue;
            else
            {
                perror("epoll_wait");
                DEBUG_LOG( "epoll wait error");
                exit(EXIT_FAILURE);
            }
        }
        
        for (i = 0; i < nfds; ++ i) {
            
            events = epoll_events[i].events;
            
            if(events & EPOLLIN)
            {
                udp_recvfrom(epoll_events[i].data.fd, udp_process);                
            }
            else if(events & (EPOLLERR | EPOLLHUP))
            {                        
                DEBUG_LOG("error condiction, events: %d, efd: %d\n", events, epoll_fd);
                if(close(epoll_events[i].data.fd) == -1)
                {
                    perror("close");
                    DEBUG_LOG( "close error");
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
}
