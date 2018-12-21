#ifndef __LINUX_UDP_H__
#define __LINUX_UDP_H__

/*----------------------------------------------*
 *宏定义                                       *
 *----------------------------------------------*/
    
#define MAX_THREAD              (32)
#define MAX_MTU_LEN             (1500)
#define FIRST_CORE              (1)
#define MAX_EVENT               (32)
#define MAX_SOCKET              (1024)
#define INVALID_SOCKET  		(-1)
    
#define  CPU_CORE_DEFAULT       (0xFFFFFFFF)       /*默认配置，系统管理CPU的分配 */
#define  MAX_MSG_LENGTH         (1024*1024)        /*最大发送消息长度*/
#define  MAX_MSG                (512)

#define	__EX(oc, ic, rs, m, x)  (oc(( (ic(x)) >> rs)&m))
#define	YGETBYTE(x,n)	        __EX( (unsigned char), (unsigned long), (8*(n)), 0x000000FF, (x) )


typedef void  (*thread_func)     ( void *threadData);


/** Get rid of path in filename - only for unix-type paths using '/' */
#define _NO_PATH_(file_name) (strrchr((file_name), '/') ? \
				  strrchr((file_name), '/') + 1 : (file_name))

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)

#define TIMEVAL_NSEC(ts)                                                       \
	((ts)->tv_sec * 1000000000ULL + (ts)->tv_usec * 1000ULL)
	
#define NSEC_TIMESPEC(ns)                                                      \
	(struct timespec) { (ns) / 1000000000ULL, (ns) % 1000000000ULL }
    
#define NSEC_TIMEVAL(ns)                                                       \
	(struct timeval)                                                       \
	{                                                                      \
		(ns) / 1000000000ULL, ((ns) % 1000000000ULL) / 1000ULL         \
	}
    
#define MSEC_NSEC(ms) ((ms)*1000000ULL)

#define __DFILENAME__ \
                (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define DEBUG_LOG(fmt, ...)    do{\
        fprintf(stderr, "[%s:%d] " fmt "\n",   \
                  __DFILENAME__, __LINE__,    \
                 ##__VA_ARGS__);					\
        }while (0)


#define __cache_aligned   __attribute__((__aligned__(64)))


/*----------------------------------------------*
 *结构体定义                                    *
 *----------------------------------------------*/
    
typedef struct {
    void                 *priData;
    thread_func           process;
    int                   core_id;
    int                   epfd;
    int                   socket_num;
    int                   len;
    int                   delay;
    pthread_t             thread_id;
   
    uint64_t              recv_calls;	/**< Number of recv() function calls */
    uint64_t              recv_bytes;	/**< Bytes received */
    uint64_t              send_calls;	/**< Number of send() function calls */
    uint64_t              send_bytes;	/**< Bytes sent */
    
    int                   sfd[MAX_SOCKET];
    struct sockaddr_in    saddr[MAX_SOCKET];
}udp_process_t __cache_aligned;

/*----------------------------------------------*
 * 内部函数原型说明                             *
 *----------------------------------------------*/
int udp_epoll_creat(void);
void udp_epoll_add(int efd, int sfd);
int udp_creat_server(const struct sockaddr_in *address);
void udp_epoll_loop(void *threadData);


int udp_creat_client(struct sockaddr_in *laddr );
void udp_send_loop(void *threadData);


#endif /*__LINUX_UDP_H__*/

