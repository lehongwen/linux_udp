#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>

#include "linux_udp.h"


int udp_creat_client(struct sockaddr_in *laddr )
{
    int client_fd;
    
    client_fd = socket(AF_INET, SOCK_DGRAM, 0);

#if 0
    if (INVALID_SOCKET == bind(client_fd, (struct sockaddr *)laddr, sizeof(*laddr)))
    {
        perror( "Can't bind socket\n");
        DEBUG_LOG("setsockopt error");
        exit(EXIT_FAILURE);
    }
#endif

    return client_fd;
}


void udp_send_loop(void *threadData)
{
    udp_process_t *udp_process = (udp_process_t*)threadData;
    
	char buf[MAX_MTU_LEN] = "123456789 987654321";
    
    struct sockaddr_in    *remote_addr = NULL;
    
    DEBUG_LOG("send udp_process(0x%x), udp_process->len(%d)",
                             udp_process,  udp_process->len);

    while(1) {

        int i, iRet, sfd;
        
        for(i = 0; i< udp_process->socket_num; i++)
        {
           sfd =  udp_process->sfd[i];
           if(sfd)
           {
               remote_addr = &(udp_process->saddr[i]);
                
               char pkt_buf[MAX_MTU_LEN] = {0};
               
               snprintf(pkt_buf, MAX_MTU_LEN-1,"send[%d] to %u.%u.%u.%u:%hu <%s>\n",
                                                sfd,
                                                YGETBYTE(remote_addr->sin_addr.s_addr, 0),
                                                YGETBYTE(remote_addr->sin_addr.s_addr, 1),
                                                YGETBYTE(remote_addr->sin_addr.s_addr, 2),
                                                YGETBYTE(remote_addr->sin_addr.s_addr, 3),
                                                ntohs(remote_addr->sin_port), buf);

                iRet = sendto(sfd, pkt_buf, udp_process->len, 0,
                              (struct sockaddr *)remote_addr, sizeof(struct sockaddr_in));
                
        		if (iRet == -1)
        			perror("sendto error");

                //udp_process->calls[i] += 1;
                //udp_process->bytes[i] += l4_len;
                
                //DEBUG_LOG("coreid[%d] send[%d] from %s at PORT %d\n", 
                //           udp_process->core_id,sfd, inet_ntop(AF_INET, &remote_addr->sin_addr, str, sizeof(str)),
                //           ntohs(remote_addr->sin_port));

               udp_process->send_calls += 1;
               udp_process->send_bytes += iRet;
                              
               //DEBUG_LOG("send calls(%d),bytes(%d),udp_process->len(%d)",
               //          udp_process->calls, udp_process->bytes, udp_process->len);
           }
        }

        if(udp_process->delay)
            sleep(udp_process->delay);
    }
}

