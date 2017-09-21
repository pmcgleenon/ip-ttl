#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>


int matches_udp(uint16_t port, int perc) {
    return matches_value(ntohs(port), perc);
}

int matches_ip(uint32_t ip, int perc) {
   return matches_value(ntohl(ip), perc);
}

int matches_value(uint32_t val, int perc) {

    if (perc == 100) {
        return 1;
    } else if (perc == 0) {
        return 0;
    }

    return ((val % (int)100/(perc)) == 0);
}

void test_ports() {
    int i;
    uint32_t port;
    int udp_count;
    int res;

    for (i=0; i<=100; i++) {
        udp_count = 0;
        for (port = 1; port < 65535; port++) {
        res = matches_udp(port, i);
        if (res == 1) {
            udp_count++;
         }
        }
        printf("[%d] udp_count = %d : %d %%\n", i, udp_count, (int)(0.5+(100.0*udp_count)/65535));
    }
}

void test_ips() {
    int i;
    uint32_t ip;
    int ip_count;
    int res;

    for (i=0; i<=100; i++) {
        ip_count = 0;
        for (ip = 1; ip < 2147483647; ip++) {
            res = matches_ip(ip, i);
            if (res == 1) {
                ip_count++;
            }
        }
        printf("[%d] ip_count = %d : %d %%\n", i, ip_count, (int)(0.5+(100.0*ip_count)/2147483647));
    }
}


int main() {

    test_ports();
    test_ips();
}

