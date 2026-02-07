#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define BASE_ADDR 0x1000ULL
#define LD_MACRO_INSTRS 12
#define LD_MACRO_BYTES (LD_MACRO_INSTRS * 4)

static void failNow(const char *message)
{
    fprintf(stderr, "Error: %s\n", message);
    exit(1);
}

static void failNowFmt(const char *fmt, const char *arg)
{
    fprintf(stderr, "Error: ");
    fprintf(stderr, fmt, arg);
    fprintf(stderr, "\n");
    exit(1);
}

static char *dupText(const char *s)
{
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    if (p == NULL)
    {
        failNow("out of memory");
    }
    memcpy(p, s, n + 1);
    return p;
}

static void trimRight(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || isspace((unsigned char)s[n - 1]) != 0))
    {
        s[n - 1] = '\0';
        n--;
    }
}

static void cutLineAtSemicolon(char *s)
{
    char *sc = strchr(s, ';');
    if (sc != NULL)
    {
        *sc = '\0';
    }
}

static const char *skipSpaces(const char *s)
{
    while (*s != '\0' && isspace((unsigned char)*s) != 0)
    {
        s++;
    }
    return s;
}

static bool beginsWith(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static void writeU32LE(FILE *f, uint32_t x)
{
    uint8_t b[4];
    b[0] = (uint8_t)(x & 0xFF);
    b[1] = (uint8_t)((x >> 8) & 0xFF);
    b[2] = (uint8_t)((x >> 16) & 0xFF);
    b[3] = (uint8_t)((x >> 24) & 0xFF);
    if (fwrite(b, 1, 4, f) != 4)
    {
        failNow("failed writing output");
    }
}

static void writeU64LE(FILE *f, uint64_t x)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++)
    {
        b[i] = (uint8_t)((x >> (8 * i)) & 0xFF);
    }
    if (fwrite(b, 1, 8, f) != 8)
    {
        failNow("failed writing output");
    }
}

static int readRegister(const char *token)
{
    if (token == NULL)
    {
        return -1;
    }
    if (!(token[0] == 'r' || token[0] == 'R'))
    {
        return -1;
    }
    char *end = NULL;
    long v = strtol(token + 1, &end, 10);
    if (end == NULL || *end != '\0')
    {
        return -1;
    }
    if (v < 0 || v > 31)
    {
        return -1;
    }
    return (int)v;
}

static bool readU64(const char *token, uint64_t *out)
{
    if (token == NULL || *token == '\0')
    {
        return false;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(token, &end, 0);
    if (errno != 0)
    {
        return false;
    }
    if (end == NULL || *end != '\0')
    {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

static bool readI12(const char *token, int32_t *out)
{
    if (token == NULL || *token == '\0')
    {
        return false;
    }
    char *end = NULL;
    errno = 0;
    long v = strtol(token, &end, 0);
    if (errno != 0)
    {
        return false;
    }
    if (end == NULL || *end != '\0')
    {
        return false;
    }
    if (v < -2048 || v > 2047)
    {
        return false;
    }
    *out = (int32_t)v;
    return true;
}

static bool readU12(const char *token, uint32_t *out)
{
    uint64_t v = 0;
    if (readU64(token, &v) == false)
    {
        return false;
    }
    if (v > 0xFFFULL)
    {
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

typedef struct
{
    char **words;
    int count;
} WordList;

static void freeWordList(WordList *w)
{
    for (int i = 0; i < w->count; i++)
    {
        free(w->words[i]);
    }
    free(w->words);
    w->words = NULL;
    w->count = 0;
}

static WordList splitWords(const char *line)
{
    WordList w = {0};
    size_t cap = 8;
    w.words = (char **)malloc(sizeof(char *) * cap);
    if (w.words == NULL)
    {
        failNow("out of memory");
    }

    const char *p = line;
    while (*p != '\0')
    {
        while (*p != '\0' && (isspace((unsigned char)*p) != 0 || *p == ','))
        {
            p++;
        }
        if (*p == '\0')
        {
            break;
        }
        const char *start = p;
        while (*p != '\0' && isspace((unsigned char)*p) == 0 && *p != ',')
        {
            p++;
        }
        size_t len = (size_t)(p - start);
        char *token = (char *)malloc(len + 1);
        if (token == NULL)
        {
            failNow("out of memory");
        }
        memcpy(token, start, len);
        token[len] = '\0';

        if (w.count == (int)cap)
        {
            cap *= 2;
            w.words = (char **)realloc(w.words, sizeof(char *) * cap);
            if (w.words == NULL)
            {
                failNow("out of memory");
            }
        }
        w.words[w.count++] = token;
    }
    return w;
}

static bool allDigits(const char *s)
{
    if (s == NULL || *s == '\0')
    {
        return false;
    }
    for (const char *p = s; *p != '\0'; p++)
    {
        if (isdigit((unsigned char)*p) == 0)
        {
            return false;
        }
    }
    return true;
}

static void toUnsignedDecimal(const char *token, char *out, size_t outsz)
{
    uint64_t v = 0;
    if (readU64(token, &v) == false)
    {
        failNow("malformed unsigned number");
    }
    snprintf(out, outsz, "%llu", (unsigned long long)v);
}

static void toSignedDecimal(const char *token, char *out, size_t outsz)
{
    char *end = NULL;
    errno = 0;
    long long v = strtoll(token, &end, 0);
    if (errno != 0 || end == NULL || *end != '\0')
    {
        failNow("malformed signed number");
    }
    snprintf(out, outsz, "%lld", v);
}

static int countCommas(const char *s)
{
    int c = 0;
    for (const char *p = s; p != NULL && *p != '\0'; p++)
    {
        if (*p == ',')
        {
            c++;
        }
    }
    return c;
}

typedef struct
{
    char *name;
    uint64_t addr;
} NamedMark;

typedef struct
{
    NamedMark *items;
    size_t count;
    size_t cap;
} MarkTable;

static void rememberMark(MarkTable *t, const char *name, uint64_t addr)
{
    for (size_t i = 0; i < t->count; i++)
    {
        if (strcmp(t->items[i].name, name) == 0)
        {
            failNowFmt("duplicate label: %s", name);
        }
    }
    if (t->count == t->cap)
    {
        t->cap = (t->cap != 0) ? (t->cap * 2) : 64;
        t->items = (NamedMark *)realloc(t->items, t->cap * sizeof(NamedMark));
        if (t->items == NULL)
        {
            failNow("out of memory");
        }
    }
    t->items[t->count].name = dupText(name);
    t->items[t->count].addr = addr;
    t->count++;
}

static bool lookupMark(const MarkTable *t, const char *name, uint64_t *out)
{
    for (size_t i = 0; i < t->count; i++)
    {
        if (strcmp(t->items[i].name, name) == 0)
        {
            *out = t->items[i].addr;
            return true;
        }
    }
    return false;
}

static void freeMarks(MarkTable *t)
{
    for (size_t i = 0; i < t->count; i++)
    {
        free(t->items[i].name);
    }
    free(t->items);
    t->items = NULL;
    t->count = 0;
    t->cap = 0;
}

typedef enum
{
    AREA_NONE,
    AREA_CODE,
    AREA_DATA
} Area;

typedef enum
{
    LINE_DIR,
    LINE_INSTR,
    LINE_DATA,
    LINE_LD_MARK
} LineKind;

typedef struct
{
    LineKind kind;
    uint64_t addr;
    Area dirArea;
    char *text;
    uint64_t data;
    int ldTarget;
    char *ldName;
} ProgramLine;

typedef struct
{
    ProgramLine *lines;
    size_t count;
    size_t cap;
} Program;

static void addLine(Program *p, ProgramLine line)
{
    if (p->count == p->cap)
    {
        p->cap = (p->cap != 0) ? (p->cap * 2) : 64;
        p->lines = (ProgramLine *)realloc(p->lines, p->cap * sizeof(ProgramLine));
        if (p->lines == NULL)
        {
            failNow("out of memory");
        }
    }
    p->lines[p->count++] = line;
}

static void freeProgram(Program *p)
{
    for (size_t i = 0; i < p->count; i++)
    {
        free(p->lines[i].text);
        free(p->lines[i].ldName);
    }
    free(p->lines);
    p->lines = NULL;
    p->count = 0;
    p->cap = 0;
}

static void emitLoadMacro(Program *prog, uint64_t *pc, int rd, uint64_t imm)
{
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "xor r%d, r%d, r%d", rd, rd, rd);
        addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
        *pc += 4;
    }
    {
        char buf[64];
        uint64_t val = (imm >> 52) & 0xFFFULL;
        snprintf(buf, sizeof(buf), "addi r%d, %llu", rd, (unsigned long long)val);
        addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
        *pc += 4;
    }

    const int shifts[5] = {12, 12, 12, 12, 4};
    const int offs[5] = {40, 28, 16, 4, 0};

    for (int i = 0; i < 5; i++)
    {
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "shftli r%d, %d", rd, shifts[i]);
            addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
            *pc += 4;
        }
        {
            char buf[64];
            uint64_t val = (i == 4) ? (imm & 0xFULL) : ((imm >> offs[i]) & 0xFFFULL);
            snprintf(buf, sizeof(buf), "addi r%d, %llu", rd, (unsigned long long)val);
            addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
            *pc += 4;
        }
    }
}

static void emitClearMacro(Program *prog, uint64_t *pc, int rd)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "xor r%d, r%d, r%d", rd, rd, rd);
    addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
    *pc += 4;
}

static void emitHaltMacro(Program *prog, uint64_t *pc)
{
    addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText("priv r0, r0, r0, 0")});
    *pc += 4;
}

static void emitInMacro(Program *prog, uint64_t *pc, int rd, int rs)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "priv r%d, r%d, r0, 3", rd, rs);
    addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
    *pc += 4;
}

static void emitOutMacro(Program *prog, uint64_t *pc, int rd, int rs)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "priv r%d, r%d, r0, 4", rd, rs);
    addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
    *pc += 4;
}

static void emitPushMacro(Program *prog, uint64_t *pc, int rd)
{
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "mov (r31)(-8), r%d", rd);
        addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
        *pc += 4;
    }
    {
        addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText("subi r31, 8")});
        *pc += 4;
    }
}

static void emitPopMacro(Program *prog, uint64_t *pc, int rd)
{
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "mov r%d, (r31)(0)", rd);
        addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText(buf)});
        *pc += 4;
    }
    {
        addLine(prog, (ProgramLine){.kind = LINE_INSTR, .addr = *pc, .text = dupText("addi r31, 8")});
        *pc += 4;
    }
}

static char *normalizeInstructionKeepMarks(const char *line)
{
    WordList w = splitWords(line);
    if (w.count == 0)
    {
        freeWordList(&w);
        return dupText("");
    }

    for (char *c = w.words[0]; *c != '\0'; c++)
    {
        *c = (char)tolower((unsigned char)*c);
    }

    size_t cap = 128;
    char *out = (char *)malloc(cap);
    if (out == NULL)
    {
        freeWordList(&w);
        failNow("out of memory");
    }
    out[0] = '\0';

#define APPEND_TEXT(S)                             \
    do                                             \
    {                                              \
        size_t need = strlen(out) + strlen(S) + 1; \
        if (need > cap)                            \
        {                                          \
            while (need > cap)                     \
            {                                      \
                cap *= 2;                          \
            }                                      \
            out = (char *)realloc(out, cap);       \
            if (out == NULL)                       \
            {                                      \
                freeWordList(&w);                  \
                failNow("out of memory");          \
            }                                      \
        }                                          \
        strcat(out, (S));                          \
    } while (0)

    APPEND_TEXT(w.words[0]);
    for (int i = 1; i < w.count; i++)
    {
        if (i == 1)
        {
            APPEND_TEXT(" ");
        }
        else
        {
            APPEND_TEXT(", ");
        }

        const char *tok = w.words[i];
        char buf[128];
        const char *emit = tok;

        if (tok[0] == ':' && tok[1] != '\0')
        {
            emit = tok;
        }
        else if (tok[0] == '-' || tok[0] == '+')
        {
            toSignedDecimal(tok, buf, sizeof(buf));
            emit = buf;
        }
        else if (beginsWith(tok, "0x") || beginsWith(tok, "0X") || allDigits(tok))
        {
            toUnsignedDecimal(tok, buf, sizeof(buf));
            emit = buf;
        }
        APPEND_TEXT(emit);
    }

#undef APPEND_TEXT
    freeWordList(&w);
    return out;
}

static char *readLabelName(const char *line)
{
    if (line == NULL || line[0] != ':')
    {
        failNow("internal: expected ':' label");
    }
    const char *p = line + 1;

    if (*p == '\0' || isspace((unsigned char)*p) != 0)
    {
        failNow("malformed label token");
    }
    if (!(isalpha((unsigned char)*p) != 0 || *p == '_' || *p == '.'))
    {
        failNow("malformed label name");
    }

    const char *start = p;
    while (*p != '\0' && (isalnum((unsigned char)*p) != 0 || *p == '_' || *p == '.'))
    {
        p++;
    }
    if (*p != '\0')
    {
        failNow("malformed label token");
    }

    size_t len = (size_t)(p - start);
    char *name = (char *)malloc(len + 1);
    if (name == NULL)
    {
        failNow("out of memory");
    }
    memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

static int expectedCommaCountForMnemonic(const char *mnemonic, int tokenCount __attribute__((unused)))
{
    if (mnemonic == NULL)
    {
        return -1;
    }

    if (strcmp(mnemonic, "return") == 0 || strcmp(mnemonic, "halt") == 0)
    {
        return 0;
    }
    if (strcmp(mnemonic, "br") == 0 || strcmp(mnemonic, "brr") == 0 || strcmp(mnemonic, "call") == 0)
    {
        return 0;
    }
    if (strcmp(mnemonic, "not") == 0 || strcmp(mnemonic, "addi") == 0 || strcmp(mnemonic, "subi") == 0 || strcmp(mnemonic, "shftri") == 0 || strcmp(mnemonic, "shftli") == 0)
    {
        return 1;
    }
    if (strcmp(mnemonic, "brnz") == 0 || strcmp(mnemonic, "mov") == 0 || strcmp(mnemonic, "in") == 0 || strcmp(mnemonic, "out") == 0 || strcmp(mnemonic, "clr") == 0 || strcmp(mnemonic, "push") == 0 || strcmp(mnemonic, "pop") == 0 || strcmp(mnemonic, "ld") == 0)
    {
        if (strcmp(mnemonic, "mov") == 0 || strcmp(mnemonic, "brnz") == 0 || strcmp(mnemonic, "in") == 0 || strcmp(mnemonic, "out") == 0 || strcmp(mnemonic, "ld") == 0)
        {
            return 1;
        }
        return 0;
    }
    if (strcmp(mnemonic, "priv") == 0)
    {
        return 3;
    }
    return 2;
}

static void enforceCommasForLine(const char *raw, const char *mnemonic, int tokenCount)
{
    if (raw == NULL || mnemonic == NULL)
    {
        return;
    }
    int expected = expectedCommaCountForMnemonic(mnemonic, tokenCount);
    if (expected < 0)
    {
        return;
    }
    int found = countCommas(raw);
    if (found != expected)
    {
        failNow("malformed operand separators");
    }
}

static void buildFirstPass(const char *inputPath, Program *outLines, MarkTable *marks)
{
    FILE *f = fopen(inputPath, "r");
    if (f == NULL)
    {
        failNowFmt("cannot open input file: %s", inputPath);
    }

    Area area = AREA_NONE;
    uint64_t pc = BASE_ADDR;
    bool sawCode = false;
    char line[4096];

    while (fgets(line, sizeof(line), f) != NULL)
    {
        trimRight(line);
        cutLineAtSemicolon(line);
        trimRight(line);

        const char *p = line;
        if (*p == '\0')
        {
            continue;
        }

        if (beginsWith(p, ".code"))
        {
            sawCode = true;
            if (area != AREA_CODE)
            {
                area = AREA_CODE;
                addLine(outLines, (ProgramLine){.kind = LINE_DIR, .addr = pc, .dirArea = AREA_CODE});
            }
            else
            {
                area = AREA_CODE;
            }
            continue;
        }
        if (beginsWith(p, ".data"))
        {
            if (area != AREA_DATA)
            {
                area = AREA_DATA;
                addLine(outLines, (ProgramLine){.kind = LINE_DIR, .addr = pc, .dirArea = AREA_DATA});
            }
            else
            {
                area = AREA_DATA;
            }
            continue;
        }

        if (*p == ':')
        {
            char *name = readLabelName(p);
            rememberMark(marks, name, pc);
            free(name);
            continue;
        }

        if (*p != '\t')
        {
            failNow("code/data line must start with tab character");
        }

        if (area == AREA_NONE)
        {
            failNow("code/data line before any .code or .data directive");
        }

        while (*p == '\t')
        {
            p++;
        }
        p = skipSpaces(p);
        if (*p == '\0')
        {
            continue;
        }

        if (area == AREA_DATA)
        {
            uint64_t v = 0;
            if (readU64(p, &v) == false)
            {
                failNow("malformed data item (expected 64-bit unsigned integer)");
            }
            addLine(outLines, (ProgramLine){.kind = LINE_DATA, .addr = pc, .data = v});
            pc += 8;
            continue;
        }

        WordList w = splitWords(p);
        if (w.count == 0)
        {
            freeWordList(&w);
            continue;
        }

        for (char *c = w.words[0]; *c != '\0'; c++)
        {
            *c = (char)tolower((unsigned char)*c);
        }
        const char *mn = w.words[0];
        enforceCommasForLine(p, mn, w.count);

        if (strcmp(mn, "clr") == 0)
        {
            if (w.count != 2)
            {
                freeWordList(&w);
                failNow("clr macro expects: clr rd");
            }
            int rd = readRegister(w.words[1]);
            if (rd < 0)
            {
                freeWordList(&w);
                failNow("clr: invalid register");
            }
            emitClearMacro(outLines, &pc, rd);
            freeWordList(&w);
            continue;
        }

        if (strcmp(mn, "halt") == 0)
        {
            if (w.count != 1)
            {
                freeWordList(&w);
                failNow("halt macro expects: halt");
            }
            emitHaltMacro(outLines, &pc);
            freeWordList(&w);
            continue;
        }

        if (strcmp(mn, "in") == 0)
        {
            if (w.count != 3)
            {
                freeWordList(&w);
                failNow("in macro expects: in rd, rs");
            }
            int rd = readRegister(w.words[1]);
            int rs = readRegister(w.words[2]);
            if (rd < 0 || rs < 0)
            {
                freeWordList(&w);
                failNow("in: invalid register");
            }
            emitInMacro(outLines, &pc, rd, rs);
            freeWordList(&w);
            continue;
        }

        if (strcmp(mn, "out") == 0)
        {
            if (w.count != 3)
            {
                freeWordList(&w);
                failNow("out macro expects: out rd, rs");
            }
            int rd = readRegister(w.words[1]);
            int rs = readRegister(w.words[2]);
            if (rd < 0 || rs < 0)
            {
                freeWordList(&w);
                failNow("out: invalid register");
            }
            emitOutMacro(outLines, &pc, rd, rs);
            freeWordList(&w);
            continue;
        }

        if (strcmp(mn, "push") == 0)
        {
            if (w.count != 2)
            {
                freeWordList(&w);
                failNow("push macro expects: push rd");
            }
            int rd = readRegister(w.words[1]);
            if (rd < 0)
            {
                freeWordList(&w);
                failNow("push: invalid register");
            }
            emitPushMacro(outLines, &pc, rd);
            freeWordList(&w);
            continue;
        }

        if (strcmp(mn, "pop") == 0)
        {
            if (w.count != 2)
            {
                freeWordList(&w);
                failNow("pop macro expects: pop rd");
            }
            int rd = readRegister(w.words[1]);
            if (rd < 0)
            {
                freeWordList(&w);
                failNow("pop: invalid register");
            }
            emitPopMacro(outLines, &pc, rd);
            freeWordList(&w);
            continue;
        }

        if (strcmp(mn, "ld") == 0)
        {
            if (w.count != 3)
            {
                freeWordList(&w);
                failNow("ld macro expects: ld rd, valueOrLabel");
            }
            int rd = readRegister(w.words[1]);
            if (rd < 0)
            {
                freeWordList(&w);
                failNow("ld: invalid register");
            }
            const char *rhs = w.words[2];
            if (rhs[0] == ':' && rhs[1] != '\0')
            {
                addLine(outLines, (ProgramLine){
                                      .kind = LINE_LD_MARK,
                                      .addr = pc,
                                      .ldTarget = rd,
                                      .ldName = dupText(rhs + 1)});
                pc += LD_MACRO_BYTES;
                freeWordList(&w);
                continue;
            }
            uint64_t imm = 0;
            if (readU64(rhs, &imm) == false)
            {
                freeWordList(&w);
                failNow("ld: invalid literal");
            }
            emitLoadMacro(outLines, &pc, rd, imm);
            freeWordList(&w);
            continue;
        }

        freeWordList(&w);
        char *clean = normalizeInstructionKeepMarks(p);
        addLine(outLines, (ProgramLine){.kind = LINE_INSTR, .addr = pc, .text = clean});
        pc += 4;
    }

    fclose(f);

    if (sawCode == false)
    {
        failNow("program must have at least one .code directive");
    }
}

static Program buildFinalProgram(const Program *first, const MarkTable *marks)
{
    Program out = {0};
    uint64_t pc = BASE_ADDR;

    for (size_t i = 0; i < first->count; i++)
    {
        const ProgramLine *it = &first->lines[i];

        if (it->kind == LINE_DIR)
        {
            addLine(&out, (ProgramLine){.kind = LINE_DIR, .addr = pc, .dirArea = it->dirArea});
            continue;
        }

        if (it->kind == LINE_DATA)
        {
            addLine(&out, (ProgramLine){.kind = LINE_DATA, .addr = pc, .data = it->data});
            pc += 8;
            continue;
        }

        if (it->kind == LINE_LD_MARK)
        {
            uint64_t addr = 0;
            if (lookupMark(marks, it->ldName, &addr) == false)
            {
                failNowFmt("ld: undefined label: %s", it->ldName);
            }
            emitLoadMacro(&out, &pc, it->ldTarget, addr);
            continue;
        }

        WordList w = splitWords(it->text);
        if (w.count == 0)
        {
            freeWordList(&w);
            continue;
        }

        for (char *c = w.words[0]; *c != '\0'; c++)
        {
            *c = (char)tolower((unsigned char)*c);
        }

        const char *mn = w.words[0];

        size_t cap = 128;
        char *s = (char *)malloc(cap);
        if (s == NULL)
        {
            freeWordList(&w);
            failNow("out of memory");
        }
        s[0] = '\0';

#define APPEND_OUT(SRC)                            \
    do                                             \
    {                                              \
        size_t need = strlen(s) + strlen(SRC) + 1; \
        if (need > cap)                            \
        {                                          \
            while (need > cap)                     \
            {                                      \
                cap *= 2;                          \
            }                                      \
            s = (char *)realloc(s, cap);           \
            if (s == NULL)                         \
            {                                      \
                freeWordList(&w);                  \
                failNow("out of memory");          \
            }                                      \
        }                                          \
        strcat(s, (SRC));                          \
    } while (0)

        APPEND_OUT(w.words[0]);

        for (int k = 1; k < w.count; k++)
        {
            if (k == 1)
            {
                APPEND_OUT(" ");
            }
            else
            {
                APPEND_OUT(", ");
            }

            const char *tok = w.words[k];
            char buf[128];
            const char *emit = tok;

            if (strcmp(mn, "brr") == 0 && w.count == 2 && tok[0] == ':' && tok[1] != '\0')
            {
                uint64_t addr = 0;
                if (lookupMark(marks, tok + 1, &addr) == false)
                {
                    freeWordList(&w);
                    free(s);
                    failNowFmt("undefined label reference: %s", tok + 1);
                }
                long long rel = (long long)((int64_t)addr - (int64_t)(pc + 4));
                if (rel < -2048LL || rel > 2047LL)
                {
                    freeWordList(&w);
                    free(s);
                    failNow("brr label out of range for signed 12-bit");
                }
                snprintf(buf, sizeof(buf), "%lld", rel);
                emit = buf;
            }
            else if (tok[0] == ':' && tok[1] != '\0')
            {
                uint64_t addr = 0;
                if (lookupMark(marks, tok + 1, &addr) == false)
                {
                    freeWordList(&w);
                    free(s);
                    failNowFmt("undefined label reference: %s", tok + 1);
                }
                snprintf(buf, sizeof(buf), "%llu", (unsigned long long)addr);
                emit = buf;
            }
            else if (tok[0] == '-' || tok[0] == '+')
            {
                toSignedDecimal(tok, buf, sizeof(buf));
                emit = buf;
            }
            else if (beginsWith(tok, "0x") || beginsWith(tok, "0X") || allDigits(tok))
            {
                toUnsignedDecimal(tok, buf, sizeof(buf));
                emit = buf;
            }

            APPEND_OUT(emit);
        }

#undef APPEND_OUT
        freeWordList(&w);

        addLine(&out, (ProgramLine){.kind = LINE_INSTR, .addr = pc, .text = s});
        pc += 4;
    }

    return out;
}

static uint32_t packR(uint32_t op, uint32_t rd, uint32_t rs, uint32_t rt)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | ((rt & 0x1F) << 12);
}

static uint32_t packI(uint32_t op, uint32_t rd, uint32_t rs, uint32_t imm12)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | (imm12 & 0xFFF);
}

static uint32_t packPriv(uint32_t op, uint32_t rd, uint32_t rs, uint32_t rt, uint32_t imm12)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | ((rt & 0x1F) << 12) | (imm12 & 0xFFF);
}

static uint32_t assembleOne(const char *instr)
{
    WordList w = splitWords(instr);
    if (w.count == 0)
    {
        freeWordList(&w);
        failNow("empty instruction");
    }

    for (char *c = w.words[0]; *c != '\0'; c++)
    {
        *c = (char)tolower((unsigned char)*c);
    }

    const char *mn = w.words[0];

    int rd = -1;
    int rs = -1;
    int rt = -1;
    uint32_t u12 = 0;
    int32_t i12 = 0;

    if (strcmp(mn, "and") == 0 || strcmp(mn, "or") == 0 || strcmp(mn, "xor") == 0 ||
        strcmp(mn, "add") == 0 || strcmp(mn, "sub") == 0 || strcmp(mn, "mul") == 0 || strcmp(mn, "div") == 0 ||
        strcmp(mn, "addf") == 0 || strcmp(mn, "subf") == 0 || strcmp(mn, "mulf") == 0 || strcmp(mn, "divf") == 0 ||
        strcmp(mn, "shftr") == 0 || strcmp(mn, "shftl") == 0)
    {
        if (w.count != 4)
        {
            freeWordList(&w);
            failNow("R-type expects 3 registers");
        }
        rd = readRegister(w.words[1]);
        rs = readRegister(w.words[2]);
        rt = readRegister(w.words[3]);
        if (rd < 0 || rs < 0 || rt < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }

        uint32_t op = 0;
        if (strcmp(mn, "and") == 0)
        {
            op = 0x0;
        }
        else if (strcmp(mn, "or") == 0)
        {
            op = 0x1;
        }
        else if (strcmp(mn, "xor") == 0)
        {
            op = 0x2;
        }
        else if (strcmp(mn, "shftr") == 0)
        {
            op = 0x4;
        }
        else if (strcmp(mn, "shftl") == 0)
        {
            op = 0x6;
        }
        else if (strcmp(mn, "addf") == 0)
        {
            op = 0x14;
        }
        else if (strcmp(mn, "subf") == 0)
        {
            op = 0x15;
        }
        else if (strcmp(mn, "mulf") == 0)
        {
            op = 0x16;
        }
        else if (strcmp(mn, "divf") == 0)
        {
            op = 0x17;
        }
        else if (strcmp(mn, "add") == 0)
        {
            op = 0x18;
        }
        else if (strcmp(mn, "sub") == 0)
        {
            op = 0x1a;
        }
        else if (strcmp(mn, "mul") == 0)
        {
            op = 0x1c;
        }
        else if (strcmp(mn, "div") == 0)
        {
            op = 0x1d;
        }
        else
        {
            freeWordList(&w);
            failNow("unknown r-type");
        }

        freeWordList(&w);
        return packR(op, (uint32_t)rd, (uint32_t)rs, (uint32_t)rt);
    }

    if (strcmp(mn, "not") == 0)
    {
        if (w.count != 3)
        {
            freeWordList(&w);
            failNow("not expects 2 registers");
        }
        rd = readRegister(w.words[1]);
        rs = readRegister(w.words[2]);
        if (rd < 0 || rs < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        freeWordList(&w);
        return packR(0x3, (uint32_t)rd, (uint32_t)rs, 0);
    }

    if (strcmp(mn, "addi") == 0 || strcmp(mn, "subi") == 0 || strcmp(mn, "shftri") == 0 || strcmp(mn, "shftli") == 0)
    {
        if (w.count != 3)
        {
            freeWordList(&w);
            failNow("I-type expects rd, imm");
        }
        rd = readRegister(w.words[1]);
        if (rd < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        if (readU12(w.words[2], &u12) == false)
        {
            freeWordList(&w);
            failNow("immediate must be 0..4095");
        }

        uint32_t op = 0;
        if (strcmp(mn, "addi") == 0)
        {
            op = 0x19;
        }
        else if (strcmp(mn, "subi") == 0)
        {
            op = 0x1b;
        }
        else if (strcmp(mn, "shftri") == 0)
        {
            op = 0x5;
        }
        else
        {
            op = 0x7;
        }

        freeWordList(&w);
        return packI(op, (uint32_t)rd, 0, u12);
    }

    if (strcmp(mn, "br") == 0)
    {
        if (w.count != 2)
        {
            freeWordList(&w);
            failNow("br expects rd");
        }
        rd = readRegister(w.words[1]);
        if (rd < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        freeWordList(&w);
        return packR(0x8, (uint32_t)rd, 0, 0);
    }

    if (strcmp(mn, "brr") == 0)
    {
        if (w.count != 2)
        {
            freeWordList(&w);
            failNow("brr expects rd or imm");
        }
        int r = readRegister(w.words[1]);
        if (r >= 0)
        {
            freeWordList(&w);
            return packR(0x9, (uint32_t)r, 0, 0);
        }
        if (readI12(w.words[1], &i12) == false)
        {
            freeWordList(&w);
            failNow("brr immediate must fit signed 12-bit");
        }
        uint32_t imm12 = (uint32_t)((int32_t)i12 & 0xFFF);
        freeWordList(&w);
        return ((0x0a & 0x1F) << 27) | (imm12 & 0xFFF);
    }

    if (strcmp(mn, "brnz") == 0)
    {
        if (w.count != 3)
        {
            freeWordList(&w);
            failNow("brnz expects rd, rs");
        }
        rd = readRegister(w.words[1]);
        rs = readRegister(w.words[2]);
        if (rd < 0 || rs < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        freeWordList(&w);
        return packR(0x0b, (uint32_t)rd, (uint32_t)rs, 0);
    }

    if (strcmp(mn, "call") == 0)
    {
        if (w.count != 2)
        {
            freeWordList(&w);
            failNow("call expects rd");
        }
        rd = readRegister(w.words[1]);
        if (rd < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        freeWordList(&w);
        return packR(0x0c, (uint32_t)rd, 0, 0);
    }

    if (strcmp(mn, "return") == 0)
    {
        if (w.count != 1)
        {
            freeWordList(&w);
            failNow("return expects no operands");
        }
        freeWordList(&w);
        return ((0x0d & 0x1F) << 27);
    }

    if (strcmp(mn, "brgt") == 0)
    {
        if (w.count != 4)
        {
            freeWordList(&w);
            failNow("brgt expects rd, rs, rt");
        }
        rd = readRegister(w.words[1]);
        rs = readRegister(w.words[2]);
        rt = readRegister(w.words[3]);
        if (rd < 0 || rs < 0 || rt < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        freeWordList(&w);
        return packR(0x0e, (uint32_t)rd, (uint32_t)rs, (uint32_t)rt);
    }

    if (strcmp(mn, "priv") == 0)
    {
        if (w.count != 5)
        {
            freeWordList(&w);
            failNow("priv expects rd, rs, rt, imm");
        }
        rd = readRegister(w.words[1]);
        rs = readRegister(w.words[2]);
        rt = readRegister(w.words[3]);
        if (rd < 0 || rs < 0 || rt < 0)
        {
            freeWordList(&w);
            failNow("invalid register");
        }
        if (readU12(w.words[4], &u12) == false)
        {
            freeWordList(&w);
            failNow("priv imm must be 0..4095");
        }
        freeWordList(&w);
        return packPriv(0x0f, (uint32_t)rd, (uint32_t)rs, (uint32_t)rt, u12);
    }

    if (strcmp(mn, "mov") == 0)
    {
        if (w.count != 3)
        {
            freeWordList(&w);
            failNow("mov expects 2 operands");
        }

        const char *a = w.words[1];
        const char *b = w.words[2];

        if (a[0] == '(')
        {
            const char *p = a + 1;
            char regbuf[16] = {0};
            int k = 0;

            while (*p != '\0' && *p != ')' && k < 15)
            {
                regbuf[k++] = *p++;
            }
            regbuf[k] = '\0';

            if (*p != ')')
            {
                freeWordList(&w);
                failNow("mov store: malformed operand");
            }
            p++;

            if (*p != '(')
            {
                freeWordList(&w);
                failNow("mov store: expected second ()");
            }
            p++;

            char immbuf[32] = {0};
            k = 0;
            while (*p != '\0' && *p != ')' && k < 31)
            {
                immbuf[k++] = *p++;
            }
            immbuf[k] = '\0';

            if (*p != ')')
            {
                freeWordList(&w);
                failNow("mov store: malformed imm");
            }
            p++;
            if (*p != '\0')
            {
                freeWordList(&w);
                failNow("mov store: trailing junk");
            }

            int base = readRegister(regbuf);
            int32_t imm = 0;

            if (base < 0)
            {
                freeWordList(&w);
                failNow("mov store: invalid base reg");
            }
            if (readI12(immbuf, &imm) == false)
            {
                freeWordList(&w);
                failNow("mov store: imm must fit signed 12-bit");
            }

            rs = readRegister(b);
            if (rs < 0)
            {
                freeWordList(&w);
                failNow("mov store: invalid source reg");
            }

            freeWordList(&w);
            return packPriv(0x13, (uint32_t)base, (uint32_t)rs, 0, (uint32_t)imm & 0xFFF);
        }

        if (b[0] == '(')
        {
            rd = readRegister(a);
            if (rd < 0)
            {
                freeWordList(&w);
                failNow("mov load: invalid rd");
            }

            const char *p = b + 1;
            char regbuf[16] = {0};
            int k = 0;

            while (*p != '\0' && *p != ')' && k < 15)
            {
                regbuf[k++] = *p++;
            }
            regbuf[k] = '\0';

            if (*p != ')')
            {
                freeWordList(&w);
                failNow("mov load: malformed operand");
            }
            p++;

            if (*p != '(')
            {
                freeWordList(&w);
                failNow("mov load: expected second ()");
            }
            p++;

            char immbuf[32] = {0};
            k = 0;
            while (*p != '\0' && *p != ')' && k < 31)
            {
                immbuf[k++] = *p++;
            }
            immbuf[k] = '\0';

            if (*p != ')')
            {
                freeWordList(&w);
                failNow("mov load: malformed imm");
            }
            p++;
            if (*p != '\0')
            {
                freeWordList(&w);
                failNow("mov load: trailing junk");
            }

            int base = readRegister(regbuf);
            int32_t imm = 0;

            if (base < 0)
            {
                freeWordList(&w);
                failNow("mov load: invalid base reg");
            }
            if (readI12(immbuf, &imm) == false)
            {
                freeWordList(&w);
                failNow("mov load: imm must fit signed 12-bit");
            }

            freeWordList(&w);
            return packPriv(0x10, (uint32_t)rd, (uint32_t)base, 0, (uint32_t)imm & 0xFFF);
        }

        rd = readRegister(a);
        if (rd < 0)
        {
            freeWordList(&w);
            failNow("mov: invalid rd");
        }

        rs = readRegister(b);
        if (rs >= 0)
        {
            freeWordList(&w);
            return packR(0x11, (uint32_t)rd, (uint32_t)rs, 0);
        }

        if (readU12(b, &u12) == false)
        {
            freeWordList(&w);
            failNow("mov rd, L: L must be 0..4095");
        }

        freeWordList(&w);
        return packI(0x12, (uint32_t)rd, 0, u12);
    }

    freeWordList(&w);
    failNowFmt("unknown instruction mnemonic: %s", mn);
    return 0;
}

static void writeIntermediateFile(const char *path, const Program *prog)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        failNowFmt("cannot open intermediate file: %s", path);
    }

    for (size_t i = 0; i < prog->count; i++)
    {
        const ProgramLine *it = &prog->lines[i];

        if (it->kind == LINE_DIR)
        {
            if (it->dirArea == AREA_CODE)
            {
                fprintf(f, ".code\n");
            }
            else if (it->dirArea == AREA_DATA)
            {
                fprintf(f, ".data\n");
            }
            continue;
        }

        if (it->kind == LINE_DATA)
        {
            fprintf(f, "\t%llu\n", (unsigned long long)it->data);
        }
        else if (it->kind == LINE_INSTR)
        {
            fprintf(f, "\t%s\n", it->text);
        }
    }

    fclose(f);
}

static void writeBinaryFile(const char *path, const Program *prog, const uint32_t *words)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL)
    {
        failNowFmt("cannot open binary output file: %s", path);
    }

    size_t wi = 0;
    for (size_t i = 0; i < prog->count; i++)
    {
        const ProgramLine *it = &prog->lines[i];

        if (it->kind == LINE_DIR)
        {
            continue;
        }

        if (it->kind == LINE_DATA)
        {
            writeU64LE(f, it->data);
        }
        else if (it->kind == LINE_INSTR)
        {
            writeU32LE(f, words[wi++]);
        }
    }

    fclose(f);
}

static uint32_t *preassembleAll(const Program *prog, size_t *outCount)
{
    size_t cap = 128;
    size_t n = 0;
    uint32_t *arr = (uint32_t *)malloc(sizeof(uint32_t) * cap);
    if (arr == NULL)
    {
        failNow("out of memory");
    }

    for (size_t i = 0; i < prog->count; i++)
    {
        const ProgramLine *it = &prog->lines[i];
        if (it->kind != LINE_INSTR)
        {
            continue;
        }
        uint32_t w = assembleOne(it->text);
        if (n == cap)
        {
            cap *= 2;
            arr = (uint32_t *)realloc(arr, sizeof(uint32_t) * cap);
            if (arr == NULL)
            {
                failNow("out of memory");
            }
        }
        arr[n++] = w;
    }

    *outCount = n;
    return arr;
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s input.tk intermediate.tkir output.tko\n", argv[0]);
        return 1;
    }

    const char *inputPath = argv[1];
    const char *intermediatePath = argv[2];
    const char *binaryPath = argv[3];

    Program first = {0};
    MarkTable marks = {0};

    buildFirstPass(inputPath, &first, &marks);
    Program finalProg = buildFinalProgram(&first, &marks);

    size_t wordCount = 0;
    uint32_t *words = preassembleAll(&finalProg, &wordCount);

    writeIntermediateFile(intermediatePath, &finalProg);
    writeBinaryFile(binaryPath, &finalProg, words);

    free(words);
    freeProgram(&first);
    freeProgram(&finalProg);
    freeMarks(&marks);

    return 0;
}
