#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void fail(const char *msg)
{
    printf("FAIL: %s\n", msg);
    exit(1);
}

static void run_cmd(const char *cmd)
{
    int r = system(cmd);
    if (r != 0)
        fail(cmd);
}

static uint32_t pack_r(uint32_t op, uint32_t rd, uint32_t rs, uint32_t rt)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | ((rt & 0x1F) << 12);
}

static uint32_t pack_i(uint32_t op, uint32_t rd, uint32_t rs, uint32_t imm12)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | (imm12 & 0xFFF);
}

static uint32_t pack_p(uint32_t op, uint32_t rd, uint32_t rs, uint32_t rt, uint32_t imm12)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | ((rt & 0x1F) << 12) | (imm12 & 0xFFF);
}

static void write_text_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        fail("open for write failed");
    if (fwrite(text, 1, strlen(text), f) != strlen(text))
        fail("write failed");
    fclose(f);
}

static char *read_text_normalized(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        fail("open for read failed");

    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0)
        fail("ftell failed");
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf)
        fail("malloc failed");
    if ((long)fread(buf, 1, (size_t)n, f) != n)
        fail("read failed");
    fclose(f);
    buf[n] = '\0';

    char *norm = (char *)malloc((size_t)n + 1);
    if (!norm)
        fail("malloc failed");

    size_t j = 0;
    for (long i = 0; i < n; i++)
    {
        if (buf[i] == '\r')
            continue;
        norm[j++] = buf[i];
    }
    norm[j] = '\0';
    free(buf);

    if (out_len)
        *out_len = j;
    return norm;
}

static uint8_t *read_bin(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        fail("open bin for read failed");

    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0)
        fail("ftell bin failed");
    fseek(f, 0, SEEK_SET);

    uint8_t *b = (uint8_t *)malloc((size_t)n);
    if (!b)
        fail("malloc bin failed");
    if ((long)fread(b, 1, (size_t)n, f) != n)
        fail("read bin failed");
    fclose(f);

    *out_len = (size_t)n;
    return b;
}

static void put_u32_le(uint8_t *dst, size_t off, uint32_t x)
{
    dst[off + 0] = (uint8_t)(x & 0xFF);
    dst[off + 1] = (uint8_t)((x >> 8) & 0xFF);
    dst[off + 2] = (uint8_t)((x >> 16) & 0xFF);
    dst[off + 3] = (uint8_t)((x >> 24) & 0xFF);
}

static void put_u64_le(uint8_t *dst, size_t off, uint64_t x)
{
    for (int i = 0; i < 8; i++)
        dst[off + (size_t)i] = (uint8_t)((x >> (8 * i)) & 0xFF);
}

int main(void)
{
    const char *tk =
        ".code\n"
        "\tclr r3\n"
        "\tld r0, :DATA1\n"
        "\taddi r1, 5\n"
        "\tpush r1\n"
        "\tpop r2\n"
        "\thalt\n"
        ".data\n"
        ":DATA1\n"
        "\t123\n";

    write_text_file("self.tk", tk);

#ifdef _WIN32
    run_cmd("gcc -std=c11 -O2 -Wall -Wextra -Werror Main.c -o hw3.exe");
    run_cmd(".\\hw3.exe self.tk self.tkir self.tko");
#else
    run_cmd("gcc -std=c11 -O2 -Wall -Wextra -Werror Main.c -o hw3");
    run_cmd("./hw3 self.tk self.tkir self.tko");
#endif

    const char *expected_tkir =
        ".code\n"
        "\txor r3, r3, r3\n"
        "\txor r0, r0, r0\n"
        "\taddi r0, 0\n"
        "\tshftli r0, 12\n"
        "\taddi r0, 0\n"
        "\tshftli r0, 12\n"
        "\taddi r0, 0\n"
        "\tshftli r0, 12\n"
        "\taddi r0, 0\n"
        "\tshftli r0, 12\n"
        "\taddi r0, 260\n"
        "\tshftli r0, 4\n"
        "\taddi r0, 12\n"
        "\taddi r1, 5\n"
        "\tmov (r31)(-8), r1\n"
        "\tsubi r31, 8\n"
        "\tmov r2, (r31)(0)\n"
        "\taddi r31, 8\n"
        "\tpriv r0, r0, r0, 0\n"
        ".data\n"
        "\t123\n";

    size_t got_len = 0;
    char *got = read_text_normalized("self.tkir", &got_len);

    if (strcmp(got, expected_tkir) != 0)
    {
        printf("FAIL: self.tkir mismatch\n\n--- expected ---\n%s\n--- got ---\n%s\n", expected_tkir, got);
        free(got);
        return 1;
    }
    free(got);

    uint32_t instrs[19];
    size_t k = 0;

    instrs[k++] = pack_r(0x2, 3, 3, 3);

    instrs[k++] = pack_r(0x2, 0, 0, 0);
    instrs[k++] = pack_i(0x19, 0, 0, 0);
    instrs[k++] = pack_i(0x7, 0, 0, 12);
    instrs[k++] = pack_i(0x19, 0, 0, 0);
    instrs[k++] = pack_i(0x7, 0, 0, 12);
    instrs[k++] = pack_i(0x19, 0, 0, 0);
    instrs[k++] = pack_i(0x7, 0, 0, 12);
    instrs[k++] = pack_i(0x19, 0, 0, 0);
    instrs[k++] = pack_i(0x7, 0, 0, 12);
    instrs[k++] = pack_i(0x19, 0, 0, 260);
    instrs[k++] = pack_i(0x7, 0, 0, 4);
    instrs[k++] = pack_i(0x19, 0, 0, 12);

    instrs[k++] = pack_i(0x19, 1, 0, 5);

    instrs[k++] = pack_p(0x13, 31, 1, 0, 0xFF8);
    instrs[k++] = pack_i(0x1b, 31, 0, 8);

    instrs[k++] = pack_p(0x10, 2, 31, 0, 0);
    instrs[k++] = pack_i(0x19, 31, 0, 8);

    instrs[k++] = pack_p(0x0f, 0, 0, 0, 0);

    if (k != 19)
        fail("internal: wrong instruction count");

    const size_t expected_bin_size = 19 * 4 + 8;
    uint8_t expected_bin[19 * 4 + 8];
    memset(expected_bin, 0, sizeof(expected_bin));

    for (size_t i = 0; i < 19; i++)
        put_u32_le(expected_bin, i * 4, instrs[i]);

    put_u64_le(expected_bin, 19 * 4, (uint64_t)123);

    size_t got_bin_len = 0;
    uint8_t *got_bin = read_bin("self.tko", &got_bin_len);

    if (got_bin_len != expected_bin_size)
    {
        printf("FAIL: self.tko size mismatch (expected %zu, got %zu)\n", expected_bin_size, got_bin_len);
        free(got_bin);
        return 1;
    }

    if (memcmp(got_bin, expected_bin, expected_bin_size) != 0)
    {
        printf("FAIL: self.tko bytes mismatch\n");
        free(got_bin);
        return 1;
    }

    free(got_bin);

    printf("ALL TESTS PASSED\n");
    return 0;
}
