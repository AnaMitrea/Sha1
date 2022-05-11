#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iostream>


class Sha1 {
    public:
        unsigned int* encode(char* data) {
            unsigned int origLength = strlen(data);
            uint64_t origLengthBits = origLength * 8;

            char* withOne = (char *)malloc((origLength+1));

            for (int i = 0; i < origLength; i++) {
                withOne[i] = data[i];
            }

            // 0x80 (hex) = 128 (dec)
            withOne[origLength] = 0x80;

            unsigned int newBitLen = (origLength + 1) * 8;

            // aflarea noii lungimi pentru padarea cu 0
            while (newBitLen % 512 != 448)
                newBitLen += 8;

            // padding cu 0 pana cand lungimea finală a mesajului să fie congruentă cu 448 modulo 512
            char* output = (char *)malloc((newBitLen / 8 + 8));
            for (int i = 0; i < (newBitLen/8 + 8); i++) {
                output[i] = 0;
            }

            // copierea array-ului withone in output ul paddat cu 0
            for (int i = 0; i < (origLength + 1); i++) {
                output[i] = *(withOne + i);
            }


            // pregatirea algoritmului pentru cele 80 de runde
            // ruperea in chunk uri de cate 512 bits
            // ruperea chunk urilor in 16 subarray-uri de cate 32 bits
            unsigned int outputLen = newBitLen/8 + 8;
            for (int i = 0; i < 8; i++) {
                output[outputLen -1 - i] = ((origLengthBits >> (8 * i)) & 0xFF);
            }

            unsigned int num_chunks = outputLen * 8 / 512;

            // valorile hash intiale 
            unsigned int h0 = 0x67452301;
            unsigned int h1 = 0xEFCDAB89;
            unsigned int h2 = 0x98BADCFE; 
            unsigned int h3 = 0x10325476;
            unsigned int h4 = 0xC3D2E1F0;

            // prelucrarea blocurilor de 512 biti
            // Secvența de biți „mesaj + umplere + lungimea mesajului” este împărțită în blocuri de 512 biți
            for(int i = 0; i < num_chunks; i++) {

                // initializarea lui w folosit pentru cele 80 de runde
                unsigned int* w = (unsigned int *) malloc(sizeof(int) * 80);
                for (int j = 0; j < 80; j++) {
                    w[j] = 0;
                }

                for (int j = 0; j < 16; j++) {
                    w[j] =  ((output[i * 512 / 8 + 4 * j] << 24) & 0xFF000000) | ((output[i * 512 / 8 + 4 * j + 1] << 16) & 0x00FF0000);
                    w[j] |= ((output[i * 512 / 8 + 4 * j + 2] << 8) & 0xFF00) | (output[i * 512 / 8 + 4 * j + 3] & 0xFF);
                }

                for (int j = 16; j < 80; j++) {
                    w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }

                // valorile hash initiale
                unsigned int a = h0;
                unsigned int b = h1;
                unsigned int c = h2;
                unsigned int d = h3;
                unsigned int e = h4;

                unsigned int f = 0;
                unsigned int k = 0;

                // operatiile bitwise din 20 in 20 de grupari
                for(int j = 0; j < 80; j++) {
                    if (0 <= j && j <= 19) {
                        f = (b & c) | ((~b) & d);    
                        k = 0x5A827999;
                    }
                    else if (20 <= j && j <= 39) {
                        f = b ^ c ^ d; 
                        k = 0x6ED9EBA1;
                    }
                    else if (40 <= j && j <= 59) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    }
                    else if(60 <= j && j <= 79) {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    // shiftarea finala
                    unsigned int temp = leftRotate(a, 5) + f + e + k + w[j];
                    e = d;
                    d = c;
                    c = leftRotate(b, 30);
                    b = a;
                    a = temp;
                }

                h0 = h0 + a;
                h1 = h1 + b;
                h2 = h2 + c;
                h3 = h3 + d;
                h4 = h4 + e;
            }

            unsigned int* hash = (unsigned int *)malloc(sizeof(int) * 5);
            hash[0] = h0;
            hash[1] = h1;
            hash[2] = h2;
            hash[3] = h3;
            hash[4] = h4;
            return hash;
        }

        // shiftarea pe biti
        unsigned int leftRotate(unsigned int n,  unsigned int d) {
            return (n << d) | (n >> (32-d));
        }
};

int main() {
    Sha1 sha;
    char* data = "abc";

    unsigned int * hash = sha.encode(data);
    std::cout << "\"message\" : 160 bits result (5 chunks of 8 bits written in hex)" << "\n";
    printf("\"abc\": %x %x %x %x %x\n\n", hash[0], hash[1], hash[2], hash[3], hash[4]);

    data = "ABC";
    hash = sha.encode(data);
    std::cout << "\"message\" : 160 bits result (5 chunks of 8 bits written in hex)" << "\n";
    printf("\"ABC\": %x %x %x %x %x\n\n", hash[0], hash[1], hash[2], hash[3], hash[4]);

    data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hash = sha.encode(data);
    std::cout << "\"message\" : 160 bits result (5 chunks of 8 bits written in hex)" << "\n";
    printf("\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\": %x %x %x %x %x\n\n", hash[0], hash[1], hash[2], hash[3], hash[4]);

    data = "123456789";
    hash = sha.encode(data);
    std::cout << "\"message\" : 160 bits result (5 chunks of 8 bits written in hex)" << "\n";
    printf("\"123456789\": %x %x %x %x %x\n\n", hash[0], hash[1], hash[2], hash[3], hash[4]);

    data = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
    hash = sha.encode(data);
    std::cout << "\"message\" : 160 bits result (5 chunks of 8 bits written in hex)" << "\n";
    printf("\"AAAAAAAAAAAAAAAAAAAAAAAAAA\": %x %x %x %x %x\n\n", hash[0], hash[1], hash[2], hash[3], hash[4]);
}