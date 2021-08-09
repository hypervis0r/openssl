/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_SOCKETS_H
# define OSSL_INTERNAL_SOCKETS_H
# pragma once

# include <openssl/opensslconf.h>

# if defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_UEFI)
#  define NO_SYS_PARAM_H
# endif
# ifdef WIN32
#  define NO_SYS_UN_H
# endif
# ifdef OPENSSL_SYS_VMS
#  define NO_SYS_PARAM_H
#  define NO_SYS_UN_H
# endif

# ifdef OPENSSL_NO_SOCK

# elif defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
#  if defined(__DJGPP__)
#   include <sys/socket.h>
#   include <sys/un.h>
#   include <tcp.h>
#   include <netdb.h>
#  elif defined(_WIN32_WCE) && _WIN32_WCE<410
#   define getservbyname _masked_declaration_getservbyname
#  endif
#  if !defined(IPPROTO_IP)
    /* winsock[2].h was included already? */
#   include <winsock.h>
#  endif
#  ifdef getservbyname
     /* this is used to be wcecompat/include/winsock_extras.h */
#   undef getservbyname
struct servent *PASCAL getservbyname(const char *, const char *);
#  endif

#  ifdef _WIN64
/*
 * Even though sizeof(SOCKET) is 8, it's safe to cast it to int, because
 * the value constitutes an index in per-process table of limited size
 * and not a real pointer. And we also depend on fact that all processors
 * Windows run on happen to be two's-complement, which allows to
 * interchange INVALID_SOCKET and -1.
 */
#   define socket(d,t,p)   ((int)socket(d,t,p))
#   define accept(s,f,l)   ((int)accept(s,f,l))
#  endif

# else

#  ifndef NO_SYS_PARAM_H
#   include <sys/param.h>
#  endif
#  ifdef OPENSSL_SYS_VXWORKS
#   include <time.h>
#  endif

#  include <netdb.h>
#  if defined(OPENSSL_SYS_VMS_NODECC)
#   include <socket.h>
#   include <in.h>
#   include <inet.h>
#  else
#   include <sys/socket.h>
#   ifndef NO_SYS_UN_H
#    include <sys/un.h>
#    ifndef UNIX_PATH_MAX
#     define UNIX_PATH_MAX sizeof(((struct sockaddr_un *)NULL)->sun_path)
#    endif
#   endif
#   ifdef FILIO_H
#    include <sys/filio.h> /* FIONBIO in some SVR4, e.g. unixware, solaris */
#   endif
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <netinet/tcp.h>
#  endif

#  ifdef OPENSSL_SYS_AIX
#   include <sys/select.h>
#  endif

#  ifndef VMS
#   include <sys/ioctl.h>
#  else
#   if !defined(TCPIP_TYPE_SOCKETSHR) && defined(__VMS_VER) && (__VMS_VER > 70000000)
     /* ioctl is only in VMS > 7.0 and when socketshr is not used */
#    include <sys/ioctl.h>
#   endif
#   include <unixio.h>
#   if defined(TCPIP_TYPE_SOCKETSHR)
#    include <socketshr.h>
#   endif
#  endif

#  ifndef INVALID_SOCKET
#   define INVALID_SOCKET      (-1)
#  endif
# endif

/*
 * Some IPv6 implementations are broken, you can disable them in known
 * bad versions.
 */
# if !defined(OPENSSL_USE_IPV6)
#  if defined(AF_INET6)
#   define OPENSSL_USE_IPV6 1
#  else
#   define OPENSSL_USE_IPV6 0
#  endif
# endif

# define get_last_socket_error() errno
# define clear_socket_error()    errno=0

# if defined(OPENSSL_SYS_WINDOWS)
#  undef get_last_socket_error
#  undef clear_socket_error
//#  define get_last_socket_error() WSAGetLastError()
//#  define clear_socket_error()    WSASetLastError(0)
//#  define readsocket(s,b,n)       recv((s),(b),(n),0)
//#  define writesocket(s,b,n)      send((s),(b),(n),0)

typedef int(*WS2_RECV_PROC)(SOCKET sock, char* buffer, int size, int flags);
typedef int(*WS2_SEND_PROC)(SOCKET sock, char* data, int len, int flags);
typedef int(*WS2_GETLASTERROR_PROC)();
typedef int(*WS2_SETLASTERROR_PROC)(int err);

inline int readsocket(SOCKET sock, char* buffer, int size)
{
    HMODULE hWs2 = LoadLibrary(L"Ws2_32.dll");
    if (!hWs2)
        return NULL;

    WS2_RECV_PROC recv_p = GetProcAddress(hWs2, "recv");
    if (!recv_p)
        return NULL;

    return recv_p(sock, buffer, size, 0);
}

inline int writesocket(SOCKET sock, char* data, int len)
{
    HMODULE hWs2 = LoadLibrary(L"Ws2_32.dll");
    if (!hWs2)
        return NULL;

    WS2_SEND_PROC send_p = GetProcAddress(hWs2, "send");
    if (!send_p)
        return NULL;

    return send_p(sock, data, len, 0);
}

inline int get_last_socket_error(void)
{
    HMODULE hWs2 = LoadLibrary(L"Ws2_32.dll");
    if (!hWs2)
        return NULL;

    WS2_GETLASTERROR_PROC WSAGetLastError_p = GetProcAddress(hWs2, "WSAGetLastError");
    if (!WSAGetLastError_p)
        return NULL;

    return WSAGetLastError_p();
}

inline int clear_socket_error(void)
{
    HMODULE hWs2 = LoadLibrary(L"Ws2_32.dll");
    if (!hWs2)
        return NULL;

    WS2_SETLASTERROR_PROC WSASetLastError_p = GetProcAddress(hWs2, "WSASetLastError");
    if (!WSASetLastError_p)
        return NULL;

    return WSASetLastError_p(0);
}

# elif defined(__DJGPP__)
#  define WATT32
#  define WATT32_NO_OLDIES
#  define closesocket(s)          close_s(s)
#  define readsocket(s,b,n)       read_s(s,b,n)
#  define writesocket(s,b,n)      send(s,b,n,0)
# elif defined(OPENSSL_SYS_VMS)
#  define ioctlsocket(a,b,c)      ioctl(a,b,c)
#  define closesocket(s)          close(s)
#  define readsocket(s,b,n)       recv((s),(b),(n),0)
#  define writesocket(s,b,n)      send((s),(b),(n),0)
# elif defined(OPENSSL_SYS_VXWORKS)
#  define ioctlsocket(a,b,c)          ioctl((a),(b),(int)(c))
#  define closesocket(s)              close(s)
#  define readsocket(s,b,n)           read((s),(b),(n))
#  define writesocket(s,b,n)          write((s),(char *)(b),(n))
# elif defined(OPENSSL_SYS_TANDEM)
#  if defined(OPENSSL_TANDEM_FLOSS)
#   include <floss.h(floss_read, floss_write)>
#   define readsocket(s,b,n)       floss_read((s),(b),(n))
#   define writesocket(s,b,n)      floss_write((s),(b),(n))
#  else
#   define readsocket(s,b,n)       read((s),(b),(n))
#   define writesocket(s,b,n)      write((s),(b),(n))
#  endif
#  define ioctlsocket(a,b,c)      ioctl(a,b,c)
#  define closesocket(s)          close(s)
# else
#  define ioctlsocket(a,b,c)      ioctl(a,b,c)
#  define closesocket(s)          close(s)
#  define readsocket(s,b,n)       read((s),(b),(n))
#  define writesocket(s,b,n)      write((s),(b),(n))
# endif

/* also in apps/include/apps.h */
# if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#  define openssl_fdset(a, b) FD_SET((unsigned int)(a), b)
# else
#  define openssl_fdset(a, b) FD_SET(a, b)
# endif

#endif
