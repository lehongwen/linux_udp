
#define _GNU_SOURCE             
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "linux_udp.h"

typedef enum appl_mode_t {
	MODE_CLIENT = 0,
	MODE_SERVER,
} appl_mode_t;


static  char *l4_laddr       = NULL;
static  char *l4_raddr       = NULL;
static  int   l4_socket      = 1;
static  int   l4_delay       = 0;  
static  int   l4_thread_num  = 2;  
static  int   l4_port        = 50000;
static  int   l4_len         = 128;  

static  appl_mode_t l4_model = MODE_CLIENT;    

static udp_process_t global_process[MAX_THREAD] __cache_aligned;

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		   "Usage: %s OPTIONS\n"
		   "  E.g. %s -l 192.169.69.120 -r 192.169.69.140\n"
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -l, local address\n"
		   "  -r, remote address\n"		   
           "  -s, creat socket count\n"  
           "  -p, address port\n"        
           "  -m, creat socket model: 1:server, 0:client\n"   
           "   -b, send socket buffer len\n"            
           "   -t, send socket delay time\n"  
           "   -c, core thread task numbers\n"        
		   "  -h, --help  Display help and exit.\n"
		   "\n", _NO_PATH_(progname), _NO_PATH_(progname)
		);
}


typedef struct {
	int64_t tv_sec;      /**< @internal Seconds or DPDK ticks */
	int64_t tv_nsec;     /**< @internal Nanoseconds */
} linux_time_t;

/** Statistics print interval in seconds */
#define DEF_PRINT_INTERVAL 10

/* Time in nanoseconds */
#define LINUX_TIME_USEC_IN_NS	1000ULL       /**< Microsecond in nsec */
#define LINUX_TIME_MSEC_IN_NS	1000000ULL    /**< Millisecond in nsec */
#define LINUX_TIME_SEC_IN_NS	1000000000ULL /**< Second in nsec */

#define LINUX_TIME_NULL ((linux_time_t){0, 0})
static  linux_time_t     start_time;

static void parse_args(int argc, char *argv[])
{
	int opt;
	int long_index;

	size_t len;

	static struct option longopts[] = {
		{"help", no_argument, NULL, 'h'},		 
		{"local address", required_argument,
			NULL, 'l'}, 
		{"remote address", required_argument,
			NULL, 'r'}, 
		{"socket creat", required_argument,
			NULL, 's'}, 
		{"socket model", required_argument,
			NULL, 'm'},  
		{"socket buf size", required_argument,
			NULL, 'b'}, 
		{"port ip", required_argument,
			NULL, 'p'}, 
		{"delay time", required_argument,
			NULL, 't'}, 
	    {"core num", required_argument,
			NULL, 'c'}, 
		{NULL, 0, NULL, 0}
	};

	while (1) {
        
		opt = getopt_long(argc, argv, "+l:r:m:s:b:p:h:t:c:d:",
				          longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
            
    		case 'h':
    			usage(argv[0]);
    			exit(EXIT_SUCCESS);
    			break;
                
    		case 'l':
    			len = strlen(optarg);
    			if (len == 0) {
    				usage(argv[0]);
    				exit(EXIT_FAILURE);
    			}
    			len += 1;	/* add room for '\0' */
    			l4_laddr = malloc(len);
    			if ( l4_laddr == NULL) {
    				usage(argv[0]);
    				exit(EXIT_FAILURE);
    			}

    			strcpy(l4_laddr, optarg);
    			break;
                
    		case 'r':
    			len = strlen(optarg);
    			if (len == 0) {
    				usage(argv[0]);
    				exit(EXIT_FAILURE);
    			}
    			len += 1;	/* add room for '\0' */
    			l4_raddr = malloc(len);
    			if (l4_raddr == NULL) {
    				usage(argv[0]);
    				exit(EXIT_FAILURE);
    			}

    			strcpy(l4_raddr, optarg);
    			break;
                
            case 's':
    			l4_socket = atoi(optarg);
                break;
                       
            case 'c':
    			l4_thread_num = atoi(optarg);
                break;
            
            case 't':
    			l4_delay = atoi(optarg);
                break; 
            
            case 'm':
    			l4_model = atoi(optarg);    
    			break; 
            
             case 'b':
    			l4_len = atoi(optarg); 
                
                if(MAX_MTU_LEN<l4_len)
                    l4_len = MAX_MTU_LEN;
                
    			break; 
                
            case 'p':
    			l4_port = atoi(optarg);    
                if(l4_port > 65534)
                    l4_port=50000;
    			break; 
            
    		default:
    			break;
		}
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

 static void paras_dump(void)
{
    DEBUG_LOG("laddr[%s],raddr[%s],socket num[%d],model[%d], delay[%d],core num[%d], base port[%d], len[%d]",
               l4_laddr, l4_raddr, l4_socket, l4_model,l4_delay, l4_thread_num,l4_port,l4_len);

}

 static inline linux_time_t linux_time_diff(linux_time_t t2, linux_time_t t1)
 {
     linux_time_t time;
 
     time.tv_sec = t2.tv_sec - t1.tv_sec;
     time.tv_nsec = t2.tv_nsec - t1.tv_nsec;
 
     if (time.tv_nsec < 0) {
         time.tv_nsec += LINUX_TIME_SEC_IN_NS;
         --time.tv_sec;
     }
 
     return time;
 }

 static inline uint64_t linux_to_ns(linux_time_t time)
 {
     uint64_t ns;
 
     ns = time.tv_sec * LINUX_TIME_SEC_IN_NS;
     ns += time.tv_nsec;
 
     return ns;
 }

 static inline linux_time_t linux_time_local(void)
 {
     int ret;
     
     linux_time_t time;
     
     struct timespec sys_time;
 
     ret = clock_gettime(CLOCK_MONOTONIC_RAW, &sys_time);
     if (ret != 0)
     {
         DEBUG_LOG("clock_gettime failed\n");
         exit(EXIT_FAILURE);
     }
 
     time.tv_sec = sys_time.tv_sec;
     time.tv_nsec = sys_time.tv_nsec;
 
     return linux_time_diff(time, start_time);
 }

 static int linux_time_init_global(void)
 {
     int ret;
     struct timespec time;
 
     ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);
     if (ret) {
         start_time = LINUX_TIME_NULL;
     } else {
         start_time.tv_sec = time.tv_sec;
         start_time.tv_nsec = time.tv_nsec;
     }
 
     return ret;
 }

 /**
  * printing verbose statistics
  *
  */
 static void linux_print_stats(void)
 {
     int i, core_index;
     
     uint64_t rx_calls[MAX_THREAD]       = {0};
     uint64_t rx_calls_prev[MAX_THREAD]  = {0};
     uint64_t rx_cps[MAX_THREAD]         = {0};
     
     uint64_t rx_maximum_cps[MAX_THREAD] = {0};
     uint64_t rx_bits[MAX_THREAD]        = {0};
     uint64_t rx_bits_prev[MAX_THREAD]   = {0};
     
     uint64_t rx_bps[MAX_THREAD]         = {0};
     uint64_t rx_maximum_bps[MAX_THREAD] = {0};
     
     uint64_t tx_calls[MAX_THREAD]       = {0};
     uint64_t tx_calls_prev[MAX_THREAD]  = {0};
     uint64_t tx_cps[MAX_THREAD]         = {0};
     
     uint64_t tx_maximum_cps[MAX_THREAD] = {0};
     uint64_t tx_bits[MAX_THREAD]        = {0};
     uint64_t tx_bits_prev[MAX_THREAD]   = {0};
     
     uint64_t tx_bps[MAX_THREAD]         = {0};
     uint64_t tx_maximum_bps[MAX_THREAD] = {0};

     uint64_t recv_calls  = 0;    /**< Number of recv() function calls */
     uint64_t recv_bytes  = 0;    /**< Bytes received */
     uint64_t send_calls  = 0;    /**< Number of send() function calls */
     uint64_t send_bytes  = 0;    /**< Bytes sent */

     linux_time_t ts_prev;
 
     ts_prev = linux_time_local();

     while (1) {
        
         linux_time_t ts;
         linux_time_t span;
     
         uint64_t time_sec;
 
         sleep(DEF_PRINT_INTERVAL);
         
         ts = linux_time_local();
 
         span = linux_time_diff(ts, ts_prev);
 
         time_sec = linux_to_ns(span) / LINUX_TIME_SEC_IN_NS;
         if (time_sec == 0)
             continue;

        for( i = FIRST_CORE, core_index = 0; core_index < l4_thread_num; core_index++, i++) {

            udp_process_t *udp_process = &(global_process[core_index]);
            
            rx_calls[core_index]  = udp_process->recv_calls;
            rx_bits[core_index]   = udp_process->recv_bytes * 8;
            
            tx_calls[core_index]  = udp_process->send_calls;
            tx_bits[core_index]   = udp_process->send_bytes * 8;
            
            #if 0
             DEBUG_LOG("rx_calls[%d](%lld),rx_bits[%d](%lld)",
                       core_index, rx_calls[core_index], 
                      core_index, rx_bits[core_index]);
             
            DEBUG_LOG("tx_calls[%d](%lld),tx_bits[%d](%lld)",
                       core_index, tx_calls[core_index], 
                       core_index, tx_bits[core_index]);      
            #endif
            
            rx_cps[core_index] = (rx_calls[core_index] - rx_calls_prev[core_index]) / time_sec;
            if (rx_cps[core_index] > rx_maximum_cps[core_index])
               rx_maximum_cps[core_index] = rx_cps[core_index];

            rx_bps[core_index] = (rx_bits[core_index] - rx_bits_prev[core_index]) / time_sec;
            if (rx_bps[core_index] > rx_maximum_bps[core_index])
               rx_maximum_bps[core_index] = rx_bps[core_index];

            tx_cps[core_index] = (tx_calls[core_index] - tx_calls_prev[core_index]) / time_sec;
            if (tx_cps[core_index] > tx_maximum_cps[core_index])
               tx_maximum_cps[core_index] = tx_cps[core_index];

            tx_bps[core_index] = (tx_bits[core_index] - tx_bits_prev[core_index]) / time_sec;
            if (tx_bps[core_index] > tx_maximum_bps[core_index])
               tx_maximum_bps[core_index] = tx_bps[core_index];

#if 0
            DEBUG_LOG("rx_cps[%d](%lld),rx_bps[%d](%lld)",
                      core_index, rx_cps[core_index], 
                      core_index, rx_bps[core_index]);

            DEBUG_LOG("tx_cps[%d](%lld),tx_bps[%d](%lld)",
                      core_index, tx_cps[core_index], 
                      core_index, tx_bps[core_index]);
#endif

            rx_calls_prev[core_index] = rx_calls[core_index];
            rx_bits_prev[core_index]  = rx_bits[core_index];
            tx_calls_prev[core_index] = tx_calls[core_index];
            tx_bits_prev[core_index]  = tx_bits[core_index];

            recv_calls += rx_calls[core_index];         
            recv_bytes += rx_bits[core_index];
            
            send_calls += tx_calls[core_index];
            send_bytes += tx_bits[core_index]; 

            if (l4_model == MODE_SERVER)
               printf("CPU[%d]: RX %.6lf Gbps (max %.6f), %.6lf Mpps (max %.6lf)\n\n",
                      i, 
                      (double)(rx_bps[core_index]) / 1000.0 / 1000.0 / 1000.0,
                      (double)(rx_maximum_bps[core_index]) / 1000.0 / 1000.0 / 1000.0,
                      (double)(rx_cps[core_index]) / 1000.0 / 1000.0,
                      (double)(rx_maximum_cps[core_index]) / 1000.0 / 1000.0);
            else
               printf("CPU[%d]: TX %.6lf Gbps (max %.6f), %.6lf Mpps (max %.6lf)\n\n",
                      i, 
                      (double)(tx_bps[core_index]) / 1000.0 / 1000.0 / 1000.0,
                      (double)(tx_maximum_bps[core_index]) / 1000.0/ 1000.0 /1000.0, 
                      (double)(tx_cps[core_index]) / 1000.0/ 1000.0,
                      (double)(tx_maximum_cps[core_index])/ 1000.0 / 1000.0);            
        }
        
         if (l4_model == MODE_SERVER){
            if (recv_calls == 0)
                continue;

             printf("Total RX %.2lf GBytes, number of recv() calls "
                   "%llu, avg bytes per call %.2lfBytes\n\n\n",
                    (double)(recv_bytes) / 1000.0 / 1000.0 / 1000.0 / 8.0,
                    (recv_calls),
                    (double)(recv_bytes) / recv_calls / 8);
        }  else {
             if (send_calls == 0)
                 continue;

             printf("Total TX %.2lf GBytes, number of send() calls "
                    "%llu, avg bytes per call %.2lfBytes\n\n\n",
                     (double)(send_bytes) / 1000.0 / 1000.0 / 1000.0 / 8.0,
                     (send_calls),
                     (double)(send_bytes) / send_calls / 8.0);
        }
        
        ts_prev = ts;
     }
 
   
 }


 static void global_process_dump(void)
{
    int i, j;
    
    for(i = 0; i < MAX_THREAD; i++)
    {
        int core_id = global_process[i].core_id;
        if(!core_id)
            continue;
        
        udp_process_t *udp_process = &(global_process[i]);
        
        DEBUG_LOG("core id[%ld],thread id[0x%x],socket num[%d]\n",
                    udp_process->core_id, udp_process->thread_id,
                    udp_process->socket_num);
        
        struct sockaddr_in *saddr;
        
        for(j = 0; j<MAX_SOCKET; j++)
        {
            saddr = &(udp_process->saddr[j]);
            if(udp_process->sfd[j])
            {
                DEBUG_LOG("socket fd index[%d],socket fd[%d], addr[%u.%u.%u.%u:%u]",
                           j, udp_process->sfd[j],
                           YGETBYTE(saddr->sin_addr.s_addr, 0),
                           YGETBYTE(saddr->sin_addr.s_addr, 1),
                           YGETBYTE(saddr->sin_addr.s_addr, 2),
                           YGETBYTE(saddr->sin_addr.s_addr, 3),
                           ntohs(saddr->sin_port));
            }
        }
    }
}


static void format_socket(struct sockaddr_in *socket_addr, int port, char *addr_txt)
{
    memset(socket_addr, 0, sizeof(*socket_addr));
    
    socket_addr->sin_family          = AF_INET;

    if(addr_txt)
        socket_addr->sin_addr.s_addr = inet_addr((const char *)(addr_txt));
    else
        socket_addr->sin_addr.s_addr = htonl(INADDR_ANY);

	socket_addr->sin_port            = htons(port);
}


static int set_thread_core(int cpuBitMask)
{
    int i = 0;
    int nrcpus = 0;
    
    cpu_set_t mask;
    unsigned long bitmask = 0;
    
    DEBUG_LOG( "thread[%ld] bind cpuBitMask[%lu]", syscall(SYS_gettid), cpuBitMask);
    /* 继承主线程特性 */
    if(CPU_CORE_DEFAULT == cpuBitMask)
    {
        return 0;
    }
    
    /* 重新绑定默认值 */
    if(0 == cpuBitMask)
    {
        cpuBitMask = CPU_CORE_DEFAULT;
    }
    
    //CPU_ZERO(&mask);
    //CPU_SET(core, &mask);
    CPU_ZERO(&mask);
	nrcpus = sysconf(_SC_NPROCESSORS_ONLN);
    for (i = 0; i < nrcpus; i++)    
    {
        if (cpuBitMask & (0x01 << i))
        {
            /* add CPUn to cpu set */
            CPU_SET(i, &mask);
            DEBUG_LOG("processor[%d] #%d is set", nrcpus, i);
        }
    }
    
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) 
    {
        DEBUG_LOG("set thread affinity failed");
        return -1;
    }

    CPU_ZERO(&mask);

    /*查询看是否设置正确*/
    /*lint -e{119}*/
    if (pthread_getaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
    {
        DEBUG_LOG("get thread affinity failed");
        return -1;
    }

    /* get logical cpu number */
    nrcpus = sysconf(_SC_NPROCESSORS_CONF);
    for (i = 0; i < nrcpus; i++)    
    {
        if (CPU_ISSET(i, &mask))
        {
            bitmask |= (unsigned long)0x01 << i;
            DEBUG_LOG("processor #%d is set", i);
        }
    }
    
    DEBUG_LOG( "set bitmask[%#lx] ok", bitmask);
    
    return 0;
}

static void *_thread_start(void *threadData)
{
	int iRet;
    udp_process_t *udp_process = (udp_process_t*)threadData;

    iRet = set_thread_core(udp_process->core_id);
    if (iRet == -1) {
        DEBUG_LOG("set thread core error");
    }

    if(udp_process->process)
        (udp_process->process)(udp_process);
    
	return NULL;
}

static void thread_task(udp_process_t *udp_process, const char *thread_name, thread_func func)
{    
	int iRet;
    
    udp_process->process = func;
    
    iRet = pthread_create(&(udp_process->thread_id), NULL, _thread_start, udp_process);
	if (iRet != 0) {
		DEBUG_LOG("pthread create error");
        exit(EXIT_FAILURE);
	}

	iRet = pthread_setname_np(udp_process->thread_id, thread_name);
	if (iRet != 0)
	{
		DEBUG_LOG("Cannot set name for lcore thread name\n");
    }
    
	return;
}
 
static void _loop(void)
{
    uint64_t last_total_pps = 0;
	uint64_t last_total_bps = 0;
    
    uint64_t last_pps[MAX_THREAD] = {0};
    uint64_t last_bps[MAX_THREAD] = {0};
    
    //uint64_t last_calls[MAX_SOCKET] = 0, 
    //uint64_t last_bytes[MAX_SOCKET] = 0;
    
    int i, core_index;

    //int interval_time = 1000;
    
    while (1) {
        
    #if 1
        struct timeval timeout = {0};//NSEC_TIMEVAL(MSEC_NSEC(1000UL));

        timeout.tv_sec  = 10;
        timeout.tv_usec = 0;
        
        while (1) {
            
            int r = select(0, NULL, NULL, NULL, &timeout);
            if (r != 0) {
                continue;
            }
            
            if (TIMEVAL_NSEC(&timeout) == 0) {
                break;
            }
        }
#endif 
        //sleep(10);

        uint64_t now_total_pps = 0;
        uint64_t now_total_bps = 0;
        
        for( i = FIRST_CORE, core_index = 0; core_index < l4_thread_num; core_index++, i++){

            uint64_t now_pps = 0;
            uint64_t now_bps = 0;

            udp_process_t *udp_process = &(global_process[core_index]);

            if (l4_model == MODE_SERVER)
            {
                now_pps = udp_process->recv_calls;
                now_bps = udp_process->recv_bytes;
            }
            else
            {
                now_pps = udp_process->send_calls;
                now_bps = udp_process->send_bytes;
            }
           
            uint64_t delta_pps = now_pps - last_pps[core_index];
            uint64_t delta_bps = now_bps - last_bps[core_index];
            
            DEBUG_LOG("i(%d),core_index(%d)", i, core_index);
            DEBUG_LOG("now_pps(%lld),now_bps(%lld)", now_pps, now_bps);
            DEBUG_LOG("last_pps(%lld),last_bps(%lld)",last_pps[core_index],last_bps[core_index]);
            DEBUG_LOG("delta_pps(%lf), delta_bps(%lf)", delta_pps, delta_bps);

            last_pps[core_index] = now_pps;
            last_bps[core_index] = now_bps;

            now_total_pps += now_pps;
            now_total_bps += now_bps;
            
            DEBUG_LOG("coreID[%d] %7.3fMpps %7.3fMiB / %7.3fMbps",
                       i,
                       (double)delta_pps / 1000.0 / 1000.0 / 10.0,
                       (double)delta_bps / 1024.0 / 1024.0 / 10.0,
                       (double)delta_bps * 8.0 / 1000.0 / 1000.0 / 10.0 );
            
        }

        uint64_t delta_total_pps = now_total_pps - last_total_pps;
        uint64_t delta_total_bps = now_total_bps - last_total_bps;

        last_total_pps = now_total_pps;
        last_total_bps = now_total_bps;
        
        DEBUG_LOG("total:    %7.3fMpps %7.3fMiB / %7.3fMbps\n\n",
                  (double)delta_total_pps / 1000.0 / 1000.0 / 10.0,
                  (double)delta_total_bps / 1024.0 / 1024.0 / 10.0,
                  (double)delta_total_bps * 8.0 / 1000.0 / 1000.0 / 10.0 );

    }
}
    

int main(int argc, char *argv[])
{
    linux_time_init_global();
    
    parse_args(argc, argv);    

    paras_dump();

    int i, j, core_index, port;
    
    char thread_name[32] = {0};
       
    for( i = FIRST_CORE, core_index = 0; core_index < l4_thread_num ; core_index++, i++)
    {
        udp_process_t *udp_process = &(global_process[core_index]);
        
        memset(udp_process, 0, sizeof(udp_process_t));
        
        DEBUG_LOG("\n udp_process(0x%x) core id(%d),  core_index(%d)", udp_process, i, core_index);

        udp_process->core_id = (1 << i);
        
        udp_process->len     = l4_len;
        udp_process->delay   = l4_delay;
        
        if(l4_model) // server
        {
            /*  server local address
                {core id:sock count:port:ip}  udp_process 
                {4:10:50000:192.168.204.135}, udp_process[0] 4
                {5:10:51000:192.168.204.135}, udp_process[1] 5
                {6:10:52000:192.168.204.135}, udp_process[2] 6
                {7:10:53000:192.168.204.135}; udp_process[3] 7
            */
            int efd;
            
            efd = udp_epoll_creat();
            
            udp_process->epfd = efd;

            for(j = 0; j< l4_socket; j++)
            {
                struct sockaddr_in *local_addr = &(udp_process->saddr[j]);
                int server_fd;
                
                port =  l4_port + core_index*1000 + j;

                format_socket(local_addr, port, l4_laddr);

               server_fd = udp_creat_server(local_addr);
               udp_process->sfd[j] = server_fd;
               
               udp_epoll_add(efd, server_fd);

               udp_process->socket_num += 1;
            }
            
            memset(thread_name, 0, 32);
            sprintf(thread_name, "recv_%d", i);
            
            thread_task(udp_process, thread_name, udp_epoll_loop);
            
            DEBUG_LOG("%s,0x%x\n",thread_name,udp_process->thread_id );
        }
        else
        {
         /*  client remote address
            {core id:sock count:port:ip}  udp_process 
            {4:1:50000:192.168.202.135}, udp_process[0]
            {5:1:51000:192.168.202.135}, udp_process[1]
            {6:1:52000:192.168.202.135}, udp_process[2]
            {7:1:53000:192.168.202.135}; udp_process[3] 
        */
            
           for(j = 0; j < l4_socket; j++)
           {
                struct sockaddr_in *remote_addr = &(udp_process->saddr[j]);
                
                int client_fd;
                
                port =  l4_port + core_index*1000 + j;

                format_socket(remote_addr, port, l4_raddr);

                struct sockaddr_in local_addr = {0};
                
                format_socket(&local_addr, port, l4_laddr);

               client_fd =  udp_creat_client(&local_addr);
               
               udp_process->sfd[j] = client_fd;
             
               udp_process->socket_num += 1;
           }
           
            memset(thread_name, 0, 32);
            sprintf(thread_name, "send_%d",i);

            thread_task(udp_process, thread_name, udp_send_loop);
            
            DEBUG_LOG("%s,0x%x\n",thread_name,udp_process->thread_id );
        }
    }
    
    global_process_dump();
    
    linux_print_stats();

    //_loop();

	DEBUG_LOG("End Main()\n");
	
	return 0;
}

