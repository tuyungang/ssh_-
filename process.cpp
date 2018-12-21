#include "process.h"
#include "packet.h"

using namespace std;
static int sig_pipefd[2];

void sig_handler( int sig )
{
    int save_errno = errno;
    int msg = sig;
    send( sig_pipefd[1], ( char* )&msg, 1, 0 );
    errno = save_errno;
}

int setnonblocking( int fd )
{
    int old_option = fcntl( fd, F_GETFL );
    int new_option = old_option | O_NONBLOCK;
    fcntl( fd, F_SETFL, new_option );
    return old_option;
}

void addsig( int sig, void( handler )(int), bool restart )
{
    struct sigaction sa;
    memset( &sa, '\0', sizeof( sa ) );
    sa.sa_handler = handler;
    if( restart )
    {
        sa.sa_flags |= SA_RESTART;
    }
    sigfillset( &sa.sa_mask );
    assert( sigaction( sig, &sa, NULL ) != -1 );
}


void addfd( int epollfd, int fd, bool one_shot )
{
    epoll_event event;
    event.data.fd = fd;
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    if( one_shot )
    {
        event.events |= EPOLLONESHOT;
    }
    epoll_ctl( epollfd, EPOLL_CTL_ADD, fd, &event );
    setnonblocking( fd );
}

void removefd( int epollfd, int fd )
{
    epoll_ctl( epollfd, EPOLL_CTL_DEL, fd, 0 );
    close( fd );
}

/*
void modfd( int epollfd, int fd, int ev )
{
    epoll_event event;
    event.data.fd = fd;
    event.events = ev | EPOLLET | EPOLLONESHOT | EPOLLRDHUP;
    epoll_ctl( epollfd, EPOLL_CTL_MOD, fd, &event );
}
*/

/*
bool read_once( int sockfd, char* buffer, int len )
{
    int bytes_read = 0;
    memset( buffer, '\0', len );
    bytes_read = recv( sockfd, buffer, len, 0 );
    if ( bytes_read == -1 ) {
        return false;
    }
    else if ( bytes_read == 0 ) {
        return false;
    }
    printf( "read in %d bytes from socket %d with content: %s\n", bytes_read, sockfd, buffer );

    return true;
}
*/

bool write_nbytes( int sockfd, const char* buffer, int len )
{
    int bytes_write = 0;
    while ( 1 ) {   
        bytes_write = send( sockfd, buffer, len, 0 );
        if ( bytes_write == -1 ) {   
            return false;
        }   
        else if ( bytes_write == 0 ) {   
            return false;
        }   
        printf( "write out %d bytes to socket %d\n", bytes_write, sockfd );
        len -= bytes_write;
        buffer = buffer + bytes_write;
        if ( len <= 0 ) {   
            //usleep(100000);
            return true;
        }   
    }   
    return true;
}

ProcessGenerator::ProcessGenerator(int fd) 
    : m_idx(-1), m_sockfd_downstream(fd), m_stop(false), m_read_downstream_idx(0), m_read_upstream_idx(0),
    m_downstream_flag(false), m_upstream_flag(false),
    m_versionready(0), m_kexready(0), m_kexdhready(0),
    m_sessionready(0), packet()/*, channel()*/
{
    sshcrypto_kexs[] = {
        {   
            "curve25519-sha256@libssh.org",
            curve25519_dh,
            curve25519_keypair,
            crypto_scalarmult_curve25519_BYTES,       /* pk */
            crypto_scalarmult_curve25519_SCALARBYTES, /* sk */
            crypto_scalarmult_curve25519_BYTES,       /* k  */
            crypto_hash_sha256,
            crypto_hash_sha256_BYTES,
            curve25519_putsharedsecret,
            curve25519_putdhpk,
            sshcrypto_TYPENEWCRYPTO,
            0,
        },
        {   
            "ecdh-sha2-nistp256",
            nistp256_dh,
            nistp256_keypair,
            crypto_scalarmult_nistp256_BYTES + 1,   /* pk */
            crypto_scalarmult_nistp256_SCALARBYTES, /* sk */
            crypto_scalarmult_nistp256_BYTES / 2,   /* k  */
            crypto_hash_sha256,
            crypto_hash_sha256_BYTES,
            nistp256_putsharedsecret,
            nistp256_putdhpk,
            sshcrypto_TYPEOLDCRYPTO,
            0,
        },
#if 0
        {   
            "pqkexTODO",
            curve25519_dh,
            curve25519_keypair,
            crypto_scalarmult_curve25519_BYTES,       /* pk */
            crypto_scalarmult_curve25519_SCALARBYTES, /* sk */
            crypto_scalarmult_curve25519_BYTES,       /* k  */
            crypto_hash_sha256,
            crypto_hash_sha256_BYTES,
            curve25519_putsharedsecret,
            curve25519_putdhpk,
            sshcrypto_TYPEPQCRYPTO,
            0,
        },
#endif
        //{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    };


    sshcrypto_keys[] = {
        {   
            "ssh-ed25519",
            crypto_sign_ed25519,
            crypto_sign_ed25519_open,
            crypto_sign_ed25519_keypair,
            {0},
            crypto_sign_ed25519_PUBLICKEYBYTES,
            crypto_sign_ed25519_SECRETKEYBYTES,
            crypto_sign_ed25519_BYTES,
            "ed25519.pk",
            ".ed25519.sk",
            sshcrypto_TYPENEWCRYPTO,
            0,
            0,
            ed25519_putsignature,
            ed25519_putsignpk,
            ed25519_putsignpkbase64,
            ed25519_parsesignature,
            ed25519_parsesignpk,
        },
        {  
            "ecdsa-sha2-nistp256",
            crypto_sign_nistp256ecdsa,
            crypto_sign_nistp256ecdsa_open,
            crypto_sign_nistp256ecdsa_keypair,
            {0},
            crypto_sign_nistp256ecdsa_PUBLICKEYBYTES,
            crypto_sign_nistp256ecdsa_SECRETKEYBYTES,
            crypto_sign_nistp256ecdsa_BYTES,
            "nistp256ecdsa.pk",
            ".nistp256ecdsa.sk",
            sshcrypto_TYPEOLDCRYPTO,
            0,
            0,
            nistp256ecdsa_putsignature,
            nistp256ecdsa_putsignpk,
            nistp256ecdsa_putsignpkbase64,
            nistp256ecdsa_parsesignature,
            nistp256ecdsa_parsesignpk,
        },
#if 0
        {   
            "pqkeyTODO",
            crypto_sign_ed25519,
            crypto_sign_ed25519_open,
            crypto_sign_ed25519_keypair,
            {0},
            crypto_sign_ed25519_PUBLICKEYBYTES,
            crypto_sign_ed25519_SECRETKEYBYTES,
            crypto_sign_ed25519_BYTES,
            "pqkeyTODO.pk",
            ".pqkeyTODO.sk",
            sshcrypto_TYPEPQCRYPTO,
            0,
            0,
            ed25519_putsignature,
            ed25519_putsignpk,
            ed25519_putsignpkbase64,
            ed25519_parsesignature,
            ed25519_parsesignpk,
        },
#endif
        //{ 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    };

    sshcrypto_ciphers[] = {
        {   
            "chacha20-poly1305@openssh.com",
            crypto_stream_chacha20_xor,
            crypto_onetimeauth_poly1305,
            crypto_stream_chacha20_KEYBYTES * 2,
            8,
            crypto_onetimeauth_poly1305_BYTES,
            chachapoly_packet_put,
            chachapoly_packet_get,
            sshcrypto_TYPENEWCRYPTO | sshcrypto_TYPEPQCRYPTO,
            0
        },
        {   
            "aes256-ctr",
            aesctr256_xor,
            crypto_auth_hmacsha256,
            crypto_core_aes256encrypt_KEYBYTES,
            16,
            crypto_auth_hmacsha256_BYTES,
            aesctr_packet_put,
            aesctr_packet_get,
            sshcrypto_TYPEOLDCRYPTO,
            0
        },
        //{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    };

    /*
    int nRet = LoadPublicKeyfile();
    if (nRet == -1) {
        sshcrypto_keys[i].sign_flagserver = 0;
        if (errno == ENOENT) continue;
    }
    */
}

int ProcessGenerator::LoadPublicKeyfile()
{
    int fd;
    int r;
    //fd = open_read();
#ifdef O_CLOEXEC
    fd = open(fn, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
#else
    fd = open(fn, O_RDONLY | O_NONBLOCK);
    if (fd == -1) return -1;
    fcntl(fd, F_SETFD, 1);
#endif
    r = Readall(fd, x, xlen);
    close(fd);
    return r;
}

int ProcessGenerator::Readall()
{
    long long r;
    unsigned char *x = (unsigned char *)xv;

    while (xlen > 0) {
        r = xlen;
        if (r > 1048576) r = 1048576;
        r = read(fd, x, r);
        if (r == 0) errno = EPROTO;
        if (r <= 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        x += r;
        xlen -= r;
    }
    return 0;
}

ProcessGenerator::~ProcessGenerator()
{
}

void ProcessGenerator::start_spawn_process()
{
    m_process = new Process();
    int ret = socketpair(PF_UNIX, SOCK_STREAM, 0, m_process->m_pipefd);
    assert(ret == 0);
    m_process->m_pid = fork();
    assert(m_process->m_pid >= 0);
    if (m_process->m_pid > 0) {
        close(m_process->m_pipefd[1]);

    } else {
        close(m_process->m_pipefd[0]);
        m_idx = 1;
    }
}

void ProcessGenerator::run_session_process()
{
    setup_sig_pipe();
    proxy_connect_peer();

    int pipefd = m_process->m_pipefd[ 1 ];
    addfd( m_epollfd, pipefd, false);

    epoll_event events[ MAX_EVENT_NUMBER ];
    int number = 0;
    int ret = -1;
    memset(m_buffer_downstream, '\0', 4096);
    memset(m_buffer_upstream, '\0', 4096);

    while( ! m_stop )
    {
        number = epoll_wait( m_epollfd, events, MAX_EVENT_NUMBER, -1 );
        if ( ( number < 0 ) && ( errno != EINTR ) )
        {
            printf( "epoll failure\n" );
            break;
        }

        for ( int i = 0; i < number; i++ )
        {
            int sockfd = events[i].data.fd;
            if( ( sockfd == pipefd ) && ( events[i].events & EPOLLIN ) )
            {
                int client = 0;
                ret = recv( sockfd, ( char* )&client, sizeof( client ), 0 );
                if( ( ( ret < 0 ) && ( errno != EAGAIN ) ) || ret == 0 ) 
                {
                    continue;
                }
                else
                {
                }
            }
            else if( ( sockfd == sig_pipefd[0] ) && ( events[i].events & EPOLLIN ) )
            {
                int sig;
                char signals[1024];
                ret = recv( sig_pipefd[0], signals, sizeof( signals ), 0 );
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
                                    continue;
                                }
                                */
                                break;
                            }
                            case SIGTERM:
                            case SIGINT:
                            {
                                printf("exit child process\n");
                                m_stop = true;
                                break;
                            }
                            default:
                            {
                                break;
                            }
                        }
                    }
                }
            }
            else if ((sockfd == m_sockfd_upstream) &&  (events[i].events & EPOLLIN) )
            {
                if (m_sessionready == STEP_READY) {
                    goto SESSION;
                } else {
                    if (m_versionready == STEP_VERSION)
                        goto VERSION;
                    if (m_keyready == STEP_KEY)
                        goto KEY;
                    if (m_keydhready == STEP_KEYDH)
                        goto KEYDH;
                    if (m_channelready == STEP_CHANNEL)
                        goto CHANNEL;
                }

                {
                VERSION:
                   nRet = packet_version_receive_from_upstream(sockfd);
                   if (nRet == 1) {
                        goto WRITE_OUT;
                   }
                KEY:
                    nRet = packet_key_receive_from_upstream(sockfd);
                KEYDH:
                    nRet = packet_keydh_receive_from_upstream(sockfd);
                AUTH:
                    packet_auth_receive_from_upstream();
                }
                WRITE_OUT:
                    struct epoll_event event;
                    event.events = EPOLLOUT | EPOLLET | EPOLLERR;
                    event.data.fd = m_sockfd_downstream;
                    epoll_ctl(m_epollfd, EPOLL_CTL_MOD, m_sockfd_downstream, &event );
            }
            else if ((sockfd == m_sockfd_downstream) &&  (events[i].events & EPOLLIN) ) 
            {
                if (m_sessionready == STEP_READY) {
                    goto SESSION;
                } else {
                    if (m_versionready == STEP_VERSION)
                        goto VERSION;
                    if (m_keyready == STEP_KEY)
                        goto KEY;
                    if (m_keydhready == STEP_KEYDH)
                        goto KEYDH;
                    if (m_channelready == STEP_CHANNEL)
                        goto CHANNEL;
                }

                {
                VERSION:
                    packet_version_receive_from_downstream(sockfd);
                KEY:
                    packet_key_receive_from_downstream(sockfd);
                KEYDH:
                    packet_keydh_receive_from_downstream(sockfd);
                AUTH:
                    packet_auth_receive_from_downstream();
                }
                SESSION:
                WRITE_OUT:
                    struct epoll_event event;
                    event.events = EPOLLOUT | EPOLLET | EPOLLERR;
                    event.data.fd = m_sockfd_upstream;
                    epoll_ctl(m_epollfd, EPOLL_CTL_MOD, m_sockfd_upstream, &event );

            }
            else if((sockfd == m_sockfd_upstream) && (events[i].events & EPOLLOUT))
            {
                if (m_sessionready == STEP_READY) {
                    goto SESSION;
                } else {
                    if (m_versionready == STEP_VERSION)
                        goto VERSION;
                    if (m_keyready == STEP_KEY)
                        goto KEY;
                    if (m_keydhready == STEP_KEYDH)
                        goto KEYDH;
                    if (m_channelready == STEP_CHANNEL)
                        goto CHANNEL;
                }

                {
                VERSION:
                    Packet_version_send_to_upstream();
                KEY:
                    Packet_key_send_to_upstream();
                KEYDH:
                    Packet_keydh_send_to_upstream();
                }

                struct epoll_event event;
                event.events = EPOLLIN | EPOLLET | EPOLLERR;
                event.data.fd = m_sockfd_upstream;
                epoll_ctl(m_epollfd, EPOLL_CTL_MOD, m_sockfd_upstream, &event );

            }
            else if((sockfd == m_sockfd_downstream) && (events[i].events & EPOLLOUT))
            {
                if (m_sessionready == STEP_READY) {
                    goto SESSION;
                } else {
                    if (m_versionready == STEP_VERSION)
                        goto VERSION;
                    if (m_keyready == STEP_KEY)
                        goto KEY;
                    if (m_keydhready == STEP_KEYDH)
                        goto KEYDH;
                    if (m_channelready == STEP_CHANNEL)
                        goto CHANNEL;
                }

                {
                VERSION:
                    nRet = Packet_version_send_to_downstream();
                KEY:
                    Packet_key_send_to_downstream();
                KEYDH:
                    Packet_keydh_send_to_upstream();
                }

                struct epoll_event event;
                event.events = EPOLLIN | EPOLLET | EPOLLERR;
                event.data.fd = m_sockfd_downstream;
                epoll_ctl(m_epollfd, EPOLL_CTL_MOD, m_sockfd_upstream, &event );

            }
            else
            {
                continue;
            }
        }
        memset(m_buffer_downstream, '\0', 4096);
        memset(m_buffer_upstream, '\0', 4096);
        m_read_downstream_idx = 0;
        m_read_upstream_idx = 0;
    }
EXIT:
    close( pipefd );
    //close( m_listenfd );
    close( m_epollfd );
    exit(0);
}

void ProcessGenerator::run_process()
{
    if (m_idx != -1) {
        process_init()
        run_session_process();
        return;
    }
}

void ProcessGenerator::setup_sig_pipe()
{
    m_epollfd = epoll_create( 5 );
    assert( m_epollfd != -1 );

    int ret = socketpair( PF_UNIX, SOCK_STREAM, 0, sig_pipefd );
    assert( ret != -1 );

    setnonblocking( sig_pipefd[1] );
    addfd( m_epollfd, sig_pipefd[0], false);

    //setnonblocking( m_sockfd_downstream );
    addfd(m_epollfd, m_sockfd_downstream, false);

    addsig( SIGCHLD, sig_handler );
    addsig( SIGTERM, sig_handler );
    addsig( SIGINT, sig_handler );
    addsig( SIGPIPE, SIG_IGN );
}

void ProcessGenerator::proxy_connect_peer()
{
    struct sockaddr_in address;
    bzero( &address, sizeof( address ) );
    address.sin_family = AF_INET;
    inet_pton( AF_INET, "192.168.2.188", &address.sin_addr );
    address.sin_port = htons( 22 );
    m_sockfd_upstream = socket( PF_INET, SOCK_STREAM, 0 );
    printf( "connect upstream\n" );
    if( m_sockfd_upstream < 0 )
    {
    }

    int reuse = 1, on = 1;
    setsockopt(m_sockfd_upstream, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(m_sockfd_upstream, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

    if (  connect( m_sockfd_upstream, ( struct sockaddr* )&address, sizeof( address ) ) == 0  )
    {
        printf( "build connection \n");
        addfd( m_epollfd, m_sockfd_upstream, false);
    }
}

void ProcessGenerator::process_init()
{
    m_versionready = STEP_VERSION;
    m_kexready = STEP_KEX;
    m_kexdhready = STEP_KEXDH;
    m_channelready = STEP_CHANNEL;
    //m_sessionready = STEP_KEXDH;

    purge(packet, sizeof(packet));
    packet.packet_init();
}

