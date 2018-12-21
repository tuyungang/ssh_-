#ifndef _PACKET_H__
#define _PACKET_H__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include "cryto_uint32.h"

#define PACKET_UNAUTHENTICATED_MESSAGES 30
#define PACKET_LIMIT 32768
#define PACKET_FULLLIMIT 35000

#define PACKET_RECVLIMIT 131072
#define PACKET_ZEROBYTES 64

struct buf {
    unsigned char *buf;
    long long len;
    long long alloc;
};

#define buf_init(a, b, c) buf_init_(__FILE__, __LINE__, (a), (b), (c)) 
#define buf_purge(a) buf_purge_(__FILE__, __LINE__, (a)) 

extern void cleanup_(void *yv, long long ylen);
#define cleanup(x) cleanup_((x), sizeof(x))
#define purge cleaup_

void cleanup_(void *yv, long long ylen) {
    volatile char *y = (volatile char *)yv; 
    while (ylen > 0) { *y++ = 0; --ylen; }
    /*
#ifdef HASASMVOLATILEMEMORY
    __asm__ __volatile__("" : : "r"(yv) : "memory");
#endif
*/
}

void buf_init_(const char *fn, unsigned long long line, struct buf *b, unsigned char *buf, long long alloc) {
    if (!b || !buf || alloc <= 0 || alloc > 1073741824) 
        //bug_inval_(fn, line);
    b->buf = buf;
    b->len = 0;
    b->alloc = alloc;
    purge(b->buf, b->alloc);
}

class Packet
{
    public:
        Packet();
        ~Packet();
    private:
        unsigned char clientpk[sshcrypto_dh_PUBLICKEYMAX];
        unsigned char serversk[sshcrypto_dh_SECRETKEYMAX];
        unsigned char serverpk[sshcrypto_dh_PUBLICKEYMAX];
        unsigned char sharedsecret[sshcrypto_dh_MAX];
        unsigned char sm[sshcrypto_sign_MAX];
        unsigned char key[sshcrypto_cipher_KEYMAX];
        unsigned char hash[sshcrypto_hash_MAX];
        
    private:
        crypto_uint32 m_sendpacketid;
        crypto_uint32 m_receivepacketid;
        unsigned char m_versionsendspace[256];
        unsigned char m_versionreceivespace[256];
        unsigned char m_keysendspace[1024];
        unsigned char m_keyrecvspace[65536];
        unsigned char m_hashbufspace[65536];
        struct buf m_versionsend;
        struct buf m_versionreceive;
        struct buf m_keysend;
        struct buf m_keyrecv;
        struct buf m_hashbuf;
        
        unsigned char recvbufspace[4 * PACKET_FULLLIMIT + 1 + PACKET_ZEROBYTES];
        unsigned char sendbufspace[4 * PACKET_FULLLIMIT + 1];
        struct buf m_recvbuf;
        struct buf m_sendbuf;
        crypto_uint32 m_packet_length;

    public:
        void packet_init();

        int packet_version_send();
        int packet_version_receive(int sockfd);
        int packet_kex_send();
        int packet_kex_receive();
        int packet_kexdh_send();
        int packet_kexdh_receive();
        int packet_channel_open();

        int getln(int sockfd, void *xv, long long xmax);
};


#endif
