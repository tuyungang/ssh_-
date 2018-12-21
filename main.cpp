#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cassert>
#include <sys/epoll.h>
#include <signal.h>

#include <openssl/engine.h>
#include <openssl/conf.h>

#include "process.h"

using namespace std;

static int sig_parent_pipefd[2];

void sig_parent_handler( int sig )
{
    int save_errno = errno;
    int msg = sig;
    send( sig_parent_pipefd[1], ( char* )&msg, 1, 0 );
    errno = save_errno;
}


int main(int argc, char **argv)
{
    const char *ip = "192.168.2.188";
    int port = atoi( "12345" );

    char request[2048] = {0};
    char buffer[4096] = {0};
    int m_stop = false;

    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
    OPENSSL_config(NULL);

    cout << "openssl version" << SSLeay_version(SSLEAY_VERSION) << endl;

    int listenfd = socket( PF_INET, SOCK_STREAM, 0 );
    assert( listenfd >= 0 );
    struct linger tmp = { 1, 0 };
    setsockopt( listenfd, SOL_SOCKET, SO_LINGER, &tmp, sizeof( tmp ) );

    int ret = 0;
    struct sockaddr_in address;
    bzero( &address, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, ip, &address.sin_addr );
    address.sin_port = htons( port );

    ret = bind( listenfd, ( struct sockaddr* )&address, sizeof( address ) );
    assert( ret >= 0 );

    ret = listen( listenfd, 5 );
    assert( ret >= 0 );

    epoll_event events[ MAX_EVENT_NUMBER ];
    int epollfd = epoll_create( 5 );
    assert( epollfd != -1 );

    addfd( epollfd, listenfd, false );
    ret = socketpair( PF_UNIX, SOCK_STREAM, 0, sig_parent_pipefd );
    assert( ret != -1 );
    setnonblocking( sig_parent_pipefd[1] );
    addfd( epollfd, sig_parent_pipefd[0], false);

    addsig( SIGPIPE, SIG_IGN );
    addsig( SIGCHLD, sig_parent_handler );
    addsig( SIGTERM, sig_parent_handler );
    addsig( SIGINT, sig_parent_handler );
    //addsig( SIGUSR1, sig_parent_handler );

    while( !m_stop )
    {
        int number = epoll_wait( epollfd, events, MAX_EVENT_NUMBER, -1 );
        if ( ( number < 0 ) && ( errno != EINTR ) )
        {
            printf( "epoll failure\n" );
            break;
        }

        for ( int i = 0; i < number; i++ )
        {
            int sockfd = events[i].data.fd;
            if( sockfd == listenfd )
            {
                struct sockaddr_in client_address;
                socklen_t client_addrlength = sizeof( client_address );
                int connfd = accept( listenfd, ( struct sockaddr* )&client_address, &client_addrlength );
                if (connfd < 0) 
                {
                    printf( "errno is: %d\n", errno );
                    continue;
                }
                ProcessGenerator *process = new ProcessGenerator(connfd);
                process->start_spawn_process();
                process->run_process();
                //send( connfd, "SSH-2.0-oPENssh_7.5 Ubuntu-10\r\n", strlen("SSH-2.0-oPENssh_7.5 Ubuntu-10\r\n"), 0 );
            }
            else if ((sockfd == sig_parent_pipefd[0]) && (events[i].events & EPOLLIN)) 
            {
                int sig;
                char signals[1024];
                ret = recv( sig_parent_pipefd[0], signals, sizeof( signals ), 0 );
                if( ret <= 0 )
                {
                    continue;
                }
                else
                {
                    for( int i = 0; i < ret; ++i )
                    {
                        switch( signals[i] )
                        {
                            case SIGCHLD:
                            {
                                /*
                                pid_t pid;
                                int stat;
                                while ( ( pid = waitpid( -1, &stat, WNOHANG ) ) > 0 )
                                {
                                    for( int i = 0; i < m_process_number; ++i )
                                    {
                                        if( m_sub_process[i].m_pid == pid )
                                        {
                                            printf( "child %d join\n", i );
                                            close( m_sub_process[i].m_pipefd[0] );
                                            m_sub_process[i].m_pid = -1;
                                        }
                                    }
                                }
                                m_stop = true;
                                for( int i = 0; i < m_process_number; ++i )
                                {
                                    if( m_sub_process[i].m_pid != -1 )
                                    {
                                        m_stop = false;
                                    }
                                }
                                */
                                break;
                            }
                            case SIGTERM:
                            case SIGINT:
                            {
                                printf("exit main process\n");
                                m_stop = true;
                                //kill(-1, SIGUSR1);
                                /*
                                printf( "kill all the clild now\n" );
                                for( int i = 0; i < m_process_number; ++i )
                                {
                                    int pid = m_sub_process[i].m_pid;
                                    if( pid != -1 )
                                    {
                                        kill( pid, SIGTERM );
                                    }
                                }
                                */
                                break;
                            }
                            default:
                            {
                                break;
                            }
                        }
                    }
                }
                /*
                else if( events[i].events & ( EPOLLRDHUP | EPOLLHUP | EPOLLERR ) )
                {
                    removefd( epollfd, sockfd );
                }
                else if( events[i].events & EPOLLIN )
                {
                    if ( ! read_once( sockfd, buffer, 4096 ) ) {
                        removefd( epollfd, sockfd );
                    }

                    struct epoll_event event;
                    event.events = EPOLLOUT | EPOLLET | EPOLLERR;
                    event.data.fd = sockfd;
                    epoll_ctl( epollfd, EPOLL_CTL_MOD, sockfd, &event );

                }
                else if( events[i].events & EPOLLOUT )
                {
                    //strncpy(request, "SSH-2.0-oPENssh_7.5 Ubuntu-10", strlen("SSH-2.0-oPENssh_7.5 Ubuntu-10"));
                    if ( ! write_nbytes( sockfd, request, strlen( request ) ) ) {
                        removefd( epollfd, sockfd );
                    }

                    struct epoll_event event;
                    event.events = EPOLLIN | EPOLLET | EPOLLERR;
                    event.data.fd = sockfd;
                    epoll_ctl( epollfd, EPOLL_CTL_MOD, sockfd, &event );

                }
                else
                {}
                memset(buffer, '\0', 4096);
                memset(request, '\0', 2048);
                */
            }
        }
    }

    close( epollfd );
    close( listenfd );

    return 0;
}
