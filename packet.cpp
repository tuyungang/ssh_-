#include "packet.h"
#include "process.h"
#include "e.h"

Packet::Packet() 
    : m_sendpacketid(0), 
    m_receivepacketid(0),
    m_packet_length(0),
{
    
}

Packet::~Packet()
{
}

void Packet::packet_init()
{
    buf_init(m_versionsend, m_versionsendspace, sizeof(m_versionsendspace));
    buf_init(m_versionreceive, m_versionreceivespace, sizeof(m_versionreceivespace));
    buf_init(m_kexsend, m_kexsendspace, sizeof(m_kexsendspace));
    buf_init(m_kexsend, m_kexrecvspace, sizeof(m_kexrecvspace));
    buf_init(m_hashbuf, m_hashbufspace, sizeof(m_hashbufspace));
    buf_init(m_sendbuf, m_sendbufspace, sizeof(m_sendbufspace));
    buf_init(m_recvbuf, m_recvbufspace, sizeof(m_recvbufspace));
}

int Packet::packet_version_send()
{
}

int getln(int sockfd, void *xv, long long xmax)
{
    long long xlen;
    int r;
    char ch;
    char *x = (char*)xv;

    if (xmax < 1) {errno = EINVAL; return -1;}
    x[0] = 0;
    if (fd < 0) {errno = EBADF; return -1;}

    xlen = 0;
    for (;;) {
        if (xlen >= xmax - 1) { x[xmax - 1] = 0; errno = ENOMEM; return -1; }
        r = getch(fd, &ch);
        if (r != 1) { close(fd); fd = -1; break; }
        if (ch == 0) ch = '\n';
        x[xlen++] = ch;
        if (ch == '\n') break;
    }
    x[xlen] = 0;
    return r;
}

int Packet::packet_version_receive_from_downstream(int fd)
{
    int r;
    //struct buf *b = &packet.helloreceive;
    struct buf *b = &m_versionreceive_downstream;

    r = getln(0, b->buf, b->alloc);
    if (r == 0) { errno = ECONNRESET; return 0; }
    if (r != 1) return 0;
    b->len = str_len((char *)b->buf);
    if (b->len < 6) { errno = EPROTO; return 0; }
    if (b->buf[b->len - 1] == '\n') --(b->len); /* remove '\n' */
    if (b->buf[b->len - 1] == '\r') --(b->len); /* remove '\r' */
    b->buf[b->len] = 0;
    if (!byte_isequal(b->buf, 4, "SSH-")) { errno = EPROTO; return 0; }
    //log_d2("hello: client: ", (char *)b->buf);
    purge(b->buf + b->len, b->alloc - b->len);
    return 1;
}

int Packet::packet_version_receive_from_upstream(int fd)
{
    int r;
    //struct buf *b = &packet.helloreceive;
    struct buf *b = &m_versionreceive;

    r = getln(0, b->buf, b->alloc);
    if (r == 0) { errno = ECONNRESET; return 0; }
    if (r != 1) return 0;
    b->len = str_len((char *)b->buf);
    if (b->len < 6) { errno = EPROTO; return 0; }
    if (b->buf[b->len - 1] == '\n') --(b->len); /* remove '\n' */
    if (b->buf[b->len - 1] == '\r') --(b->len); /* remove '\r' */
    b->buf[b->len] = 0;
    if (!byte_isequal(b->buf, 4, "SSH-")) { errno = EPROTO; return 0; }
    //log_d2("hello: client: ", (char *)b->buf);
    purge(b->buf + b->len, b->alloc - b->len);
    return 1;
}

int Packet::writeall(int fd,const void *xv,long long xlen)
{
    char *x = (char *)xv;
    long long w;
    while (xlen > 0) {
        w = xlen;
        if (w > 1048576) w = 1048576;
        w = write(fd,x,w);
        if (w < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd p;
                p.fd = fd;
                p.events = POLLOUT | POLLERR;
                poll(&p,1,-1);
                continue;
            }
            return -1;
        }
        x += w;
        xlen -= w;
    }
    return 0;
}

int Packet_version_send_to_upstream(int fd)
{
    struct buf *b = &m_versionreceive_downstream;
    buf_puts(b, "\r\n");
    if (writeall(fd, b->buf, b->len) == -1) return 0;
    b->len -= 2;
    b->buf[b->len] = 0;
    purge(b->buf + b->len, b->alloc - b->len);
    return 1;
}

int Packet::Packet_version_send_to_downstream(int fd)
{
    struct buf *b = &m_versionreceive_upstream;
    buf_puts(b, "\r\n");
    if (writeall(fd, b->buf, b->len) == -1) return 0;
    b->len -= 2;
    b->buf[b->len] = 0;
    purge(b->buf + b->len, b->alloc - b->len);
    return 1;
}

int Packet::packet_key_send()
{
}

int Packet::packet_key_receive_from_downstream(int fd)
{

}

static int packet_get_plain_(struct buf *b) 
{
    crypto_uint32 packet_length;
    long long len;
    struct buf *recvbuf = &packet.recvbuf;
    unsigned char *pp;
    long long l;

    pp = recvbuf->buf + PACKET_ZEROBYTES;
    l  = recvbuf->len - PACKET_ZEROBYTES;

    /* we need at least 4 bytes */
    if (l < 4) return 1;

    /* parse length */
    packet_length = uint32_unpack_big(pp);
    if (packet_length > PACKET_LIMIT) {
        char buf1[NUMTOSTR_LEN];
        char buf2[NUMTOSTR_LEN];
        errno = EPROTO;
        //log_f4("packet length ", numtostr(buf1, packet_length), " > PACKET_LIMIT ", numtostr(buf2, PACKET_LIMIT));
        //global_die(111);
    }
    if (packet_length + 4 > l) return 1;

    /* we have full packet */
    len = packet_length;
    len -= recvbuf->buf[PACKET_ZEROBYTES + 4] + 1;
    if (len <= 0) bug_proto();
    buf_put(b, recvbuf->buf + PACKET_ZEROBYTES + 5, len);

    byte_copy(pp,  l - packet_length + 4, pp + packet_length + 4);
    purge(pp + l - packet_length + 4, packet_length + 4);
    recvbuf->len -= packet_length + 4;

    packet.receivepacketid++;
    return 1;
}

static int packet_get_(struct buf *b) 
{
    if (packet.flagkeys) {
        //return sshcrypto_packet_get(b);
    }
    else {
        return packet_get_plain_(b);
    }
}

int packet_get(struct buf *b, crypto_uint8 x) 
{
    buf_purge(b);
    if (!packet_get_(b)) return 0;
    if (b->len <= 0) return 1;
    if (!packet.flagauthorized) 
        if (packet.receivepacketid > PACKET_UNAUTHENTICATED_MESSAGES) {
        errno = EPROTO;
        //log_f1("too many unauthenticated messages");
        //global_die(111);
    }

    switch (b->buf[0]) {
        case SSH_MSG_DISCONNECT:
            errno = 0;
            return 0;
        case SSH_MSG_IGNORE:
        case SSH_MSG_DEBUG:
            buf_purge(b);
            break;
        default:
            if (x && x != b->buf[0]) {
                char buf1[NUMTOSTR_LEN];
                char buf2[NUMTOSTR_LEN];
                errno = EPROTO;
                //log_f4("expected packet type ", numtostr(buf1, b->buf[0]), ", got ", numtostr(buf2, x));
                //global_die(111);
            }
            break;
    }
    return 1;
}

int packet_recvisready(void) 
{
    return buf_ready(&packet.recvbuf, PACKET_FULLLIMIT);
}

int packet_recv(void) 
{
    long long r;
    struct buf *b = &packet.recvbuf;

    if (b->len < PACKET_ZEROBYTES) {
    b->len = PACKET_ZEROBYTES;
    purge(b->buf, PACKET_ZEROBYTES);
    }
    if (!packet_recvisready()) return 1;

    r = read(0, b->buf + b->len, PACKET_FULLLIMIT);
    if (r == 0) { errno = ECONNRESET; return 0; }
    if (r == -1) {
    if (errno == EINTR) return 1;
    if (errno == EAGAIN) return 1;
    if (errno == EWOULDBLOCK) return 1;
    return 0;
    }
    b->len += r;
    return 1;
}

int packet_getall(struct buf *b, crypto_uint8 ch) 
{
    struct pollfd x;
    long long before;

    buf_purge(b);

    for (;;) {
        before = packet.recvbuf.len;
        if (!packet_get(b, ch)) return 0;
        if (b->len > 0) break;
        if (before != packet.recvbuf.len) continue;
        x.fd = 0;
        x.events = POLLIN | POLLERR;
        poll(&x, 1, -1);
        if (!packet_recv()) return 0;
    }
    return 1;
}

int sshcrypto_kex_select(const unsigned char *buf, long long len, crypto_uint8 *kex_guess) 
{
    long long i, pos = 0;
    unsigned char *x;
    long long xlen;

    if (sshcrypto_kex_name) return 1;

    if (buf[len] != 0) bug_proto();
    log_d2("kex: client: kex algorithms: ", (char *)buf); 

    *kex_guess = 1;

    for (;;) {
        pos = stringparser(buf, len, pos, &x, &xlen);
        if (!pos) break;

        for (i = 0; sshcrypto_kexs[i].name; ++i) {
            if (!sshcrypto_kexs[i].flagenabled) continue;
            if (str_equaln((char *)x, xlen, sshcrypto_kexs[i].name)) {
                sshcrypto_kex_name = sshcrypto_kexs[i].name;
                sshcrypto_dh = sshcrypto_kexs[i].dh;
                sshcrypto_dh_keypair = sshcrypto_kexs[i].dh_keypair;
                sshcrypto_dh_publickeybytes = sshcrypto_kexs[i].dh_publickeybytes;
                sshcrypto_dh_secretkeybytes = sshcrypto_kexs[i].dh_secretkeybytes;
                sshcrypto_dh_bytes = sshcrypto_kexs[i].dh_bytes;
                sshcrypto_hash = sshcrypto_kexs[i].hash;
                sshcrypto_hash_bytes = sshcrypto_kexs[i].hash_bytes;
                sshcrypto_buf_putsharedsecret = sshcrypto_kexs[i].buf_putsharedsecret;
                sshcrypto_buf_putdhpk = sshcrypto_kexs[i].buf_putdhpk;
                log_d2("kex: kex selected: ", sshcrypto_kexs[i].name);
                return 1;
            }
        }
        *kex_guess = 0;
    }
    log_d2("kex: kex not available ", (char *)buf);
    errno = EPROTO;
    return 0;
}

static void packet_put_plain_(struct buf *b) 
{
    long long pos;
    crypto_uint8 paddinglen;
    struct buf *sendbuf = &packet.sendbuf;

    pos = sendbuf->len;                 /* get position */
    buf_putnum32(sendbuf, 0);           /* length */
    buf_putnum8(sendbuf, 0);            /* padding length */
    buf_put(sendbuf, b->buf, b->len);   /* add data */
    packet.sendpacketid++;              /* increment id */

    /* padding */
    paddinglen = 2 * 8 - ((sendbuf->len - pos) % 8);
    buf_putzerobytes(sendbuf, paddinglen);
    sendbuf->buf[pos + 4] = paddinglen;

    /* add packet length */
    uint32_pack_big(sendbuf->buf + pos, sendbuf->len - pos - 4);
}

void packet_put(struct buf *b) 
{
    if (packet.flagkeys) {
        //sshcrypto_packet_put(b);
    }
    else {
        packet_put_plain_(b);
    }
}

int Packet_key_send_to_upstream(int fd)
{
    struct buf *b = &kexsend_upstream;

    /* send server kex_init */
    buf_purge(b);
    buf_putnum8(b, SSH_MSG_KEXINIT);       /* SSH_MSG_KEXINIT */
    buf_putstring(b, "");
    //buf_putrandombytes(b, 16);             /* cookie */
    buf_putstring(b, "");
    //sshcrypto_kex_put(b);                  /* kex algorithms */
    buf_putstring(b, ""):
    //sshcrypto_key_put(b);                  /* server host key algorithms */
    buf_putstring(b, "");
    //sshcrypto_cipher_put(b);               /* encryption algorithms client to server */
    buf_putstring(b, "");
    //sshcrypto_cipher_put(b);               /* encryption algorithms server to client */
    buf_putstring(b, "");
    //sshcrypto_cipher_macput(b);            /* mac algorithms client to server */
    buf_putstring(b, "");
    //sshcrypto_cipher_macput(b);            /* mac algorithms server to client */
    buf_putstring(b, "none");              /* compress algorithms client to server */
    buf_putstring(b, "none");              /* compress algorithms server to client */
    buf_putstring(b, "");                  /* languages client to server */
    buf_putstring(b, "");                  /* languages server to client */
    buf_putnum8(b, 0);                     /* kex first packet follows  */
    buf_putnum32(b, 0);                    /* reserved */

    packet_put(b);
    return packet_sendall(fd);
}

int Packet_key_send_to_downstream(int fd)
{
    struct buf *b = &kexsend_upstream;

    /* send server kex_init */
    buf_purge(b);
    buf_putnum8(b, SSH_MSG_KEXINIT);       /* SSH_MSG_KEXINIT */
    buf_putstring(b, "");
    //buf_putrandombytes(b, 16);             /* cookie */
    buf_putstring(b, "");
    //sshcrypto_kex_put(b);                  /* kex algorithms */
    buf_putstring(b, ""):
    //sshcrypto_key_put(b);                  /* server host key algorithms */
    buf_putstring(b, "");
    //sshcrypto_cipher_put(b);               /* encryption algorithms client to server */
    buf_putstring(b, "");
    //sshcrypto_cipher_put(b);               /* encryption algorithms server to client */
    buf_putstring(b, "");
    //sshcrypto_cipher_macput(b);            /* mac algorithms client to server */
    buf_putstring(b, "");
    //sshcrypto_cipher_macput(b);            /* mac algorithms server to client */
    buf_putstring(b, "none");              /* compress algorithms client to server */
    buf_putstring(b, "none");              /* compress algorithms server to client */
    buf_putstring(b, "");                  /* languages client to server */
    buf_putstring(b, "");                  /* languages server to client */
    buf_putnum8(b, 0);                     /* kex first packet follows  */
    buf_putnum32(b, 0);                    /* reserved */

    packet_put(b);
    return packet_sendall(fd);
}

int packet_sendall(fd) 
{
    if (writeall(fd, packet.sendbuf.buf, packet.sendbuf.len) == -1) return 0;
    purge(packet.sendbuf.buf, packet.sendbuf.len);
    //packet.sendbuf.len = 0;
    return 1;
}


int Packet::packet_key_receive_from_upstream(int fd)
{
    //struct buf *b = &packet.kexrecv;
    struct buf *b = &keyrecv_upstream;
    long long pos = 0;
    crypto_uint8 ch;
    crypto_uint32 len;

    if (!packet_getall(b, SSH_MSG_KEXINIT)) return 0;

    /* parse packet */
    pos = packetparser_uint8(b->buf, b->len, pos, &ch);       /* SSH_MSG_KEXINIT */
    if (ch != SSH_MSG_KEXINIT) bug_proto();

    pos = packetparser_skip(b->buf, b->len, pos, 16);         /* cookie */

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* kex algorithms */
    pos = packetparser_skip(b->buf, b->len, pos, len);        
    if (!sshcrypto_kex_select(b->buf + pos - len, len, &packet.kex_guess)) return 0;

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* server host key algorithms */
    pos = packetparser_skip(b->buf, b->len, pos, len);        
    if (!sshcrypto_key_select(b->buf + pos - len, len)) return 0;

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* encryption algorithms client to server */
    pos = packetparser_skip(b->buf, b->len, pos, len);        
    if (!sshcrypto_cipher_select(b->buf + pos - len, len)) return 0;

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* encryption algorithms server to client */
    pos = packetparser_skip(b->buf, b->len, pos, len);        
    /* XXX assuming same as encryption algorithms client to server  */

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* mac algorithms client to server */
    pos = packetparser_skip(b->buf, b->len, pos, len);        
    if (!sshcrypto_cipher_macselect(b->buf + pos - len, len)) return 0;

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* mac algorithms server to client */
    pos = packetparser_skip(b->buf, b->len, pos, len);        

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* compress algorithms client to server */
    pos = packetparser_skip(b->buf, b->len, pos, len);        

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* compress algorithms server to client */
    pos = packetparser_skip(b->buf, b->len, pos, len);        

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* languages client to server */
    pos = packetparser_skip(b->buf, b->len, pos, len);        

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* languages server to client */
    pos = packetparser_skip(b->buf, b->len, pos, len);        

    pos = packetparser_uint8(b->buf, b->len, pos, &ch);       /* kex first packet follows */
    packet.kex_packet_follows = ch;

    pos = packetparser_uint32(b->buf, b->len, pos, &len);     /* reserved */
    pos = packetparser_end(b->buf, b->len, pos);

    return 1;
}

int Packet::packet_keydh_receive_from_downstream(int fd)
{
    long long pos = 0;
    int type = 0;
    crypto_uint32 len;
    crypto_uint8 ch;
    struct buf *b = &keydhrecv_downstream;

    if (!packet_getall(b, SSH_MSG_KEXDH_REPLY)) {

    }
    pos = packetparser_uint8(b->buf, b->len, pos, &ch);
    if (ch != SSH_MSG_KEXDH_INIT) {
    }
    pos = packetparser_uint32(b->buf, b->len, pos, &len);
    pos = packetparser_copy(b->buf, b->len, pos, clientpk, len);
    pos = packetparser_end(b->buf, b->len, pos);
    buf_purge(b);
}

int sshcrypto_hostkey_select(const unsigned char *buf, long long len, long long pos, int &type)
{
    int i = 0;
    char compare_string[30];
    memset(compare_string, '\0', 30);
    for (;;) {
        compare_string[i] = b->buf[pos + i];
        if (strncmp(compare_string, "ssh-rsa", strlen("ssh-rsa");) == 0) {
            type = 1;
            break;
        }
        else if (strncmp(compare_string, "ecdsa-sha2-nistp256", strlen("ecdsa-sha2-nistp256")) == 0) {
            type = 2;
            break;
        }
        else if (strncmp(compare_string, "ssh-ed25519", strlen("ssh-ed25519")) == 0) {
            type = 3;
            break;
        }
        i++;
    }
    pos += i;
    return pos;
}

unsigned char *base64_decode(const char* base64data, int* len) 
{
    BIO *b64, *bmem;
    size_t length = strlen(base64data);
    unsigned char *buffer = (unsigned char *)malloc(length);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void*)base64data, length);
    bmem = BIO_push(b64, bmem);
    *len = BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);
    return buffer;
}

BIGNUM* bignum_base64_decode(const char* base64bignum) 
{
    BIGNUM* bn = NULL;
    int len;
    unsigned char* data = base64_decode(base64bignum, &len);
    if (len) {
        bn = BN_bin2bn(data, len, NULL);
    }
    free(data);
    return bn;
}

EVP_PKEY* RSA_fromBase64(const char* modulus_b64, const char* exp_b64) 
{
    BIGNUM *n = bignum_base64_decode(modulus_b64);
    BIGNUM *e = bignum_base64_decode(exp_b64);

    if (!n) printf("Invalid encoding for modulus\n");
    if (!e) printf("Invalid encoding for public exponent\n");

    if (e && n) {
        EVP_PKEY* pRsaKey = EVP_PKEY_new();
        RSA* rsa = RSA_new();
        rsa->e = e;
        rsa->n = n;
        EVP_PKEY_assign_RSA(pRsaKey, rsa);
        return pRsaKey;
    } else {
        if (n) BN_free(n);
        if (e) BN_free(e);
        return NULL;
    }
}

int Generate_hostkey(const string &publickey_path, RSA *rsa)
{
    if (publickey_path.empty()) {
    }
    OpenSSL_add_all_algorithms();
    BIO *bp = BIO_new(BIO_s_file());
    if(BIO_write_filename(bp, (void *)publickey_path.c_str()) <= 0)
    {
        perror("Open public key file error\n");
        return (-1);
    }
    if(PEM_write_bio_RSAPublicKey(bp, rsa) != 1)
    {
        perror("Write public key error\n");
        return (-1);
    }
    printf("Save public key file successfully:%s\n",publickey_path.c_str());
    BIO_free_all(bp);
    return 0;
}

int Packet::packet_keydh_receive_from_upstream(int fd)
{
    unsigned char rsa_e[3];
    unsigned char rsa_n[257];
    long long pos = 0;
    int type = 0;
    crypto_uint32 len;
    crypto_uint32 e_len;
    crypto_uint32 m_len;
    crypto_uint8 ch;
    struct buf *b = &keydhrecv_upstream;

    if (!packet_getall(b, SSH_MSG_KEXDH_REPLY)) {

    }
    pos = packetparser_uint8(b->buf, b->len, pos, &ch);
    if (ch != SSH_MSG_KEXDH_REPLY) {
    }
    pos = packetparser_uint32(b->buf, b->len, pos, &len);
    //pos = packetparser_skip(b->buf, b->len, pos, len);
    //if (!sshcrypto_hostkey_select(b->buf)) return 0;
    pos = sshcrypto_hostkey_select(b->buf, b->len, pos, type);
    switch (type)
    {
        case 1:
            {
                pos = packetparser_uint32(b->buf, b->len, pos, &e_len);
                //pos = packetparser_skip(b->buf, b->len, pos, e_len);
                pos = packetparser_copy(b->buf, b->len, pos, rsa_e, e_len);
                pos = packetparser_uint32(b->buf, b->len, pos, &m_len);
                pos = packetparser_copy(b->buf, b->len, pos, rsa_n, m_len);
                break;
            }
        case 2:
            {
                pos = packetparser_copy(b->buf, b->len, pos, serverpk, len);
                break;
            }
        case 3:
            {
                pos = packetparser_copy(b->buf, b->len, pos, serverpk, len);
                break;
            }
        default:
            break;
    }
    pos =packetparser_uint32(b->buf, b->len, pos, &len);
    pos = packetparser_copy(b->buf, b->len, pos, serverpk, len);
    pos =packetparser_uint32(b->buf, b->len, pos, &len);
    pos = packetparser_copy(b->buf, b->len, pos, sm, len);
    buf_purge(b);

}

int Packet::packet_channel_open()
{
}

