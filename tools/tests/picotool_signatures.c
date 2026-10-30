#include "mbedtls_wrapper.h"
#include <stdio.h>
#include <string.h>

void raw_to_der(signature_t *sig);
void der_to_raw(signature_t *sig);

/* Construct positive DER INTEGERs from explicit widths, independently of
 * picotool's leading-zero scan. Cover both components and sign-bit padding. */
static size_t scalar(unsigned char *raw, unsigned char *der,
                     size_t leading_zeros, int high_bit) {
    memset(raw, 0, leading_zeros);
    memset(raw + leading_zeros, 0x5b, 32 - leading_zeros);
    raw[leading_zeros] = high_bit ? 0xa0 : 0x20;
    size_t width = 32 - leading_zeros;
    der[0] = 0x02;
    der[1] = (unsigned char)(width + high_bit);
    if (high_bit) {
        der[2] = 0;
    }
    memcpy(der + 2 + high_bit, raw + leading_zeros, width);
    return 2 + high_bit + width;
}

int main(void) {
    size_t cases = 0;
    for (size_t r_zeros = 0; r_zeros < 32; ++r_zeros) {
        for (size_t s_zeros = 0; s_zeros < 32; ++s_zeros) {
            for (int r_high = 0; r_high < 2; ++r_high) {
                for (int s_high = 0; s_high < 2; ++s_high) {
                    signature_t expected = {0};
                    expected.der[0] = 0x30;
                    size_t pos = 2;
                    pos += scalar(expected.bytes, expected.der + pos, r_zeros, r_high);
                    pos += scalar(expected.bytes + 32, expected.der + pos, s_zeros, s_high);
                    expected.der[1] = (unsigned char)(pos - 2);
                    expected.der_len = pos;

                    signature_t encoded = {0};
                    memcpy(encoded.bytes, expected.bytes, sizeof(encoded.bytes));
                    raw_to_der(&encoded);
                    if (encoded.der_len != expected.der_len ||
                        memcmp(encoded.der, expected.der, expected.der_len) != 0) {
                        fprintf(stderr, "DER encoding failure: r=%zu bytes/high=%d, s=%zu bytes/high=%d\n",
                                32 - r_zeros, r_high, 32 - s_zeros, s_high);
                        return 1;
                    }

                    signature_t decoded = {0};
                    memcpy(decoded.der, expected.der, expected.der_len);
                    decoded.der_len = expected.der_len;
                    der_to_raw(&decoded);
                    if (memcmp(decoded.bytes, expected.bytes, sizeof(decoded.bytes)) != 0) {
                        fprintf(stderr, "Raw decoding failure: r=%zu bytes/high=%d, s=%zu bytes/high=%d\n",
                                32 - r_zeros, r_high, 32 - s_zeros, s_high);
                        return 1;
                    }
                    ++cases;
                }
            }
        }
    }
    printf("%zu signature boundary cases passed\n", cases);
    return 0;
}
