#ifndef _SPAWN_PROCESS_
#define _SPAWN_PROCESS_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "e.h"

#define MAX_EVENT_NUMBER 10000

int setnonblocking( int fd );
void addsig( int sig, void( handler )(int), bool restart = true );
void addfd( int epollfd, int fd, bool one_shot );
void removefd( int epollfd, int fd );
//void sig_handler( int sig );

#define crypto_sign_ed25519_tinynacl_SECRETKEYBYTES 64
#define crypto_sign_ed25519_tinynacl_PUBLICKEYBYTES 32
#define crypto_sign_ed25519_tinynacl_BYTES 64
/*
extern int crypto_sign_ed25519_tinynacl(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_ed25519_tinynacl_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_ed25519_tinynacl_keypair(unsigned char *,unsigned char *);
*/

#define crypto_sign_ed25519 crypto_sign_ed25519_tinynacl
#define crypto_sign_ed25519_open crypto_sign_ed25519_tinynacl_open
#define crypto_sign_ed25519_keypair crypto_sign_ed25519_tinynacl_keypair
#define crypto_sign_ed25519_BYTES crypto_sign_ed25519_tinynacl_BYTES
#define crypto_sign_ed25519_PUBLICKEYBYTES crypto_sign_ed25519_tinynacl_PUBLICKEYBYTES
#define crypto_sign_ed25519_SECRETKEYBYTES crypto_sign_ed25519_tinynacl_SECRETKEYBYTES
#define crypto_sign_ed25519_IMPLEMENTATION "tinynacl"
#define crypto_sign_ed25519_VERSION "-"

struct sshcrypto_kex 
{
    const char *name;
    int (*dh)(unsigned char *, unsigned char *, unsigned char *);
    int (*dh_keypair)(unsigned char *, unsigned char *);
    long long dh_publickeybytes;
    long long dh_secretkeybytes;
    long long dh_bytes;
    int (*hash)(unsigned char *, const unsigned char *, unsigned long long);
    long long hash_bytes;
    void (*buf_putsharedsecret)(struct buf *, const unsigned char *);
    void (*buf_putdhpk)(struct buf *, const unsigned char *);
    unsigned int cryptotype;
    int flagenabled;
};

struct sshcrypto_key 
{
    const char *name;
    int (*sign)(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
    int (*sign_open)(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
    int (*sign_keypair)(unsigned char *, unsigned char *);
    unsigned char sign_publickey[sshcrypto_sign_PUBLICKEYMAX];
    long long sign_publickeybytes;
    long long sign_secretkeybytes;
    long long sign_bytes;
    const char *sign_publickeyfilename;
    const char *sign_secretkeyfilename;
    unsigned int cryptotype;
    int sign_flagserver;
    int sign_flagclient;
    void (*buf_putsignature)(struct buf *, const unsigned char *);
    void (*buf_putsignpk)(struct buf *, const unsigned char *);
    void (*buf_putsignpkbase64)(struct buf *, const unsigned char *);
    int (*parsesignature)(unsigned char *, const unsigned char *, long long);
    int (*parsesignpk)(unsigned char *, const unsigned char *, long long);
};

struct sshcrypto_cipher 
{
    const char *name;
    int (*stream_xor)(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
    int (*auth)(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
    long long stream_keybytes;
    long long cipher_blockbytes;
    long long auth_bytes;
    void (*packet_put)(struct buf *);
    int (*packet_get)(struct buf *);
    unsigned int cryptotype;
    int flagenabled;
};

class Process
{
    public:
        Process() : m_pid(-1) {}
        ~Process();
    public:
        pid_t m_pid;
        int m_pipefd[2];
        int m_used;
        int m_sessionID;
        int m_pos;
};

class ProcessGenerator
{
    public:
        static const int MAX_PROCESS_NUM = 200;
        static const int MAX_BUFFER_SIZE = 4096;
        //enum { MAX_PROCESS_NUM = 200};
        typedef enum { STEP_NONE = 0, STEP_VERSION, STEP_KEX, STEP_KEXDH, STEP_CHANNEL, STEP_READY} ENUM_EXEC_STEP;
    public:
        ProcessGenerator(int fd);
        ~ProcessGenerator();
    private:
        struct sshcrypto_key sshcrypto_keys[2]; 
        struct sshcrypto_cipher sshcrypto_ciphers[2];
        struct sshcrypto_kex sshcrypto_kexs[2];
        int m_idx;
        int m_sockfd_downstream;
        int m_sockfd_upstream;
        int m_epollfd;

        Process *m_process;
        Packet packet;
        //Channel channel;

        bool m_stop;
        char m_buffer_downstream[MAX_BUFFER_SIZE];
        char m_buffer_upstream[MAX_BUFFER_SIZE];
        int m_read_downstream_idx;
        int m_read_upstream_idx;
        int m_read_downstream_len;
        int m_read_upstream_len;
        bool m_downstream_flag;
        bool m_upstream_flag;

        ENUM_EXEC_STEP m_versionready;
        ENUM_EXEC_STEP m_kexready;
        ENUM_EXEC_STEP m_kexdhready;
        ENUM_EXEC_STEP m_channelready;
        ENUM_EXEC_STEP m_sessionready;

    public:
        void start_spawn_process();
        void process_init();
        void run_process();
        void run_session_process();
        void setup_sig_pipe();
        void proxy_connect_peer();
};

#endif
