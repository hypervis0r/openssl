Welcome to Hypervisor's fork of the OpenSSL Project
==============================

[![openssl logo]][www.openssl.org]

I created this fork to adjust some functions to be acceptable for implants.
For example, I have modified the socket implementation so WinSock2 functions are dynamically resolved at runtime.
In the future, I will do the same for certain WinAPI calls.
