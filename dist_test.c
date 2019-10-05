#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

static const int ECN_NOT_ECT = 0;
static const int ECN_ECT_1 = 1;
static const int ECN_ECT_0 = 2;
static const int ECN_CE = 3;

int matches_udp(uint16_t port, int perc11, int perc10, int perc01) {
    return matches_value(ntohs(port), perc11, perc10, perc01);
}

int matches_ip(uint32_t ip, int perc11, int perc10, int perc01) {
   return matches_value(ntohl(ip), perc11, perc10, perc01);
}

int matches_value(uint32_t match_val, int perc11, int perc10, int perc01) {

    if (perc11 == 100) {
        return ECN_CE;
    } else if (perc11 == 0 && perc10 == 0 && perc01 == 0) {
        return ECN_NOT_ECT;
    }

    if (perc11 && (match_val % (int)100/(perc11)) == 0) 
        return ECN_CE;
    else if (perc10 && (match_val % (int)(100-perc11)/perc10) == 0)
        return ECN_ECT_1;
    else if (perc01 && (match_val % (int)(100-perc11-perc10)/perc01) == 0)
        return ECN_ECT_0;
    else
        return ECN_NOT_ECT;       
   
}

void test_ports() {
    int i;
    uint32_t port;
    int ecn_ce_count = 0;
    int ecn_ect_1_count = 0;
    int ecn_ect_0_count = 0;
    int ecn_not_ect_count = 0;
    int res;

    for (i=0; i<=100; i++) {
        ecn_ce_count = 0;
        ecn_ect_1_count = 0;
        ecn_ect_0_count = 0;
        ecn_not_ect_count = 0;
        for (port = 1; port < 65535; port++) {
            res = matches_udp(port, i, i, i);
            if (res == ECN_CE) {
                ecn_ce_count++;
            }
            else if (res == ECN_ECT_1) {
                ecn_ect_1_count++;
            }
            else if (res == ECN_ECT_0) {
                ecn_ect_0_count++;
            }
            else if (res == ECN_NOT_ECT) {
                ecn_not_ect_count++;
            }
        }
        printf("[%d] ce_count = %d ect_1_count: %d ect_0_count: %d ecn_not_ect_count %d <%d><%d><%d><%d>\n", 
                 i, ecn_ce_count, ecn_ect_1_count, ecn_ect_0_count, ecn_not_ect_count, 
                 (int)(0.5+(100.0*ecn_ce_count)/65535),
                 (int)(0.5+(100.0*ecn_ect_1_count)/65535),
                 (int)(0.5+(100.0*ecn_ect_0_count)/65535),
                 (int)(0.5+(100.0*ecn_not_ect_count)/65535));
    }
}

void test_ips() {
    int i;
    uint32_t ip;
    int ecn_ce_count = 0;
    int ecn_ect_1_count = 0;
    int ecn_ect_0_count = 0;
    int ecn_not_ect_count = 0;
    int res;

    for (i=0; i<=100; i++) {
        ecn_ce_count = 0;
        ecn_ect_1_count = 0;
        ecn_ect_0_count = 0;
        ecn_not_ect_count = 0;
        for (ip = 1; ip < 2147483647; ip++) {
            res = matches_ip(ip, i, i, i);
            if (res == ECN_CE) {
                ecn_ce_count++;
            }
            else if (res == ECN_ECT_1) {
                ecn_ect_1_count++;
            }
            else if (res == ECN_ECT_0) {
                ecn_ect_0_count++;
            }
            else if (res == ECN_NOT_ECT) {
                ecn_not_ect_count++;
            }
        }
        printf("[%d] ce_count = %d ect_1_count: %d ect_0_count: %d ecn_not_ect_count %d <%d><%d><%d><%d>\n", 
                 i, ecn_ce_count, ecn_ect_1_count, ecn_ect_0_count, ecn_not_ect_count, 
                 (int)(0.5+(100.0*ecn_ce_count)/65535),
                 (int)(0.5+(100.0*ecn_ect_1_count)/65535),
                 (int)(0.5+(100.0*ecn_ect_0_count)/65535),
                 (int)(0.5+(100.0*ecn_not_ect_count)/65535));
    }
}


int main() {
    test_ports();
    test_ips();
}

