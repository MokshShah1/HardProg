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
    char *p = malloc(n + 1);
    if (!p)
        failNow("out of memory");
    memcpy(p, s, n + 1);
    return p;
}

static void trimRight(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (isspace((unsigned char)s[n - 1]) || s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static void cutLineAtSemicolon(char *s)
{
    char *p = strchr(s, ';');
    if (p)
        *p = '\0';
}

static const char *skipSpaces(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return s;
}

static bool beginsWith(const char *s, const char *p)
{
    return strncmp(s, p, strlen(p)) == 0;
}

static int readRegister(const char *t)
{
    if (!t || (t[0] != 'r' && t[0] != 'R'))
        return -1;
    char *e;
    long v = strtol(t + 1, &e, 10);
    if (*e || v < 0 || v > 31)
        return -1;
    return (int)v;
}

static bool readU64(const char *t, uint64_t *o)
{
    char *e;
    errno = 0;
    unsigned long long v = strtoull(t, &e, 0);
    if (errno || *e)
        return false;
    *o = v;
    return true;
}

static bool readI12(const char *t, int32_t *o)
{
    char *e;
    errno = 0;
    long v = strtol(t, &e, 0);
    if (errno || *e || v < -2048 || v > 2047)
        return false;
    *o = (int32_t)v;
    return true;
}

static bool readU12(const char *t, uint32_t *o)
{
    uint64_t v;
    if (!readU64(t, &v) || v > 0xFFF)
        return false;
    *o = (uint32_t)v;
    return true;
}

typedef struct
{
    char **w;
    int n;
} Words;

static Words splitWords(const char *l)
{
    Words r = {0};
    int cap = 8;
    r.w = malloc(sizeof(char *) * cap);
    if (!r.w)
        failNow("out of memory");

    while (*l)
    {
        while (*l && (isspace((unsigned char)*l) || *l == ','))
            l++;
        if (!*l)
            break;
        const char *s = l;
        while (*l && !isspace((unsigned char)*l) && *l != ',')
            l++;
        int len = l - s;
        char *t = malloc(len + 1);
        memcpy(t, s, len);
        t[len] = 0;
        if (r.n == cap)
        {
            cap *= 2;
            r.w = realloc(r.w, sizeof(char *) * cap);
            if (!r.w)
                failNow("out of memory");
        }
        r.w[r.n++] = t;
    }
    return r;
}

static void freeWords(Words *w)
{
    for (int i = 0; i < w->n; i++)
        free(w->w[i]);
    free(w->w);
}

typedef struct
{
    char *name;
    uint64_t addr;
} Label;
typedef struct
{
    Label *a;
    size_t n, c;
} LabelTable;

static void addLabel(LabelTable *t, const char *n, uint64_t a)
{
    for (size_t i = 0; i < t->n; i++)
        if (!strcmp(t->a[i].name, n))
            failNowFmt("duplicate label: %s", n);
    if (t->n == t->c)
    {
        t->c = t->c ? t->c * 2 : 32;
        t->a = realloc(t->a, sizeof(Label) * t->c);
        if (!t->a)
            failNow("out of memory");
    }
    t->a[t->n++] = (Label){dupText(n), a};
}

static bool findLabel(const LabelTable *t, const char *n, uint64_t *o)
{
    for (size_t i = 0; i < t->n; i++)
        if (!strcmp(t->a[i].name, n))
        {
            *o = t->a[i].addr;
            return true;
        }
    return false;
}

static void freeLabels(LabelTable *t)
{
    for (size_t i = 0; i < t->n; i++)
        free(t->a[i].name);
    free(t->a);
}

typedef enum
{
    NONE,
    CODE,
    DATA
} Section;
typedef enum
{
    INST,
    DATA_WORD,
    LD_LABEL
} LineKind;

typedef struct
{
    LineKind kind;
    uint64_t addr;
    char *text;
    uint64_t data;
    int reg;
    char *label;
} Line;

typedef struct
{
    Line *a;
    size_t n, c;
} Program;

static void addLine(Program *p, Line l)
{
    if (p->n == p->c)
    {
        p->c = p->c ? p->c * 2 : 64;
        p->a = realloc(p->a, sizeof(Line) * p->c);
        if (!p->a)
            failNow("out of memory");
    }
    p->a[p->n++] = l;
}

static char *readLabelName(const char *l)
{
    l = skipSpaces(l + 1);
    const char *s = l;
    while (*l && (isalnum((unsigned char)*l) || *l == '_' || *l == '.'))
        l++;
    char *r = malloc(l - s + 1);
    memcpy(r, s, l - s);
    r[l - s] = 0;
    return r;
}

static void buildFirstPass(const char *path, Program *out, LabelTable *labels)
{
    FILE *f = fopen(path, "r");
    if (!f)
        failNowFmt("cannot open input file: %s", path);

    Section sec = NONE;
    uint64_t pc = BASE_ADDR;
    char buf[4096];

    while (fgets(buf, sizeof(buf), f))
    {
        trimRight(buf);
        cutLineAtSemicolon(buf);
        trimRight(buf);
        const char *p = skipSpaces(buf);
        if (!*p)
            continue;

        if (beginsWith(p, ".code"))
        {
            sec = CODE;
            continue;
        }
        if (beginsWith(p, ".data"))
        {
            sec = DATA;
            continue;
        }

        if (*p == ':')
        {
            if (sec == DATA)
                failNow("labels not allowed in .data section");
            char *n = readLabelName(p);
            addLabel(labels, n, pc);
            free(n);
            continue;
        }

        if (*p != '\t')
            failNow("code/data line must start with tab character");
        p = skipSpaces(p + 1);
        if (!*p)
            continue;

        if (sec == DATA)
        {
            uint64_t v;
            if (!readU64(p, &v))
                failNow("malformed data item");
            addLine(out, (Line){DATA_WORD, pc, NULL, v, 0, NULL});
            pc += 8;
            continue;
        }

        Words w = splitWords(p);
        if (w.n == 0)
        {
            freeWords(&w);
            continue;
        }

        if (!strcmp(w.w[0], "ld") && w.n == 3 && w.w[2][0] == ':')
        {
            addLine(out, (Line){LD_LABEL, pc, NULL, 0, readRegister(w.w[1]), dupText(w.w[2] + 1)});
            pc += LD_MACRO_BYTES;
            freeWords(&w);
            continue;
        }

        freeWords(&w);
        Words check = splitWords(p);
        if (check.n == 0)
            failNow("invalid instruction");
        freeWords(&check);

        addLine(out, (Line){INST, pc, dupText(p), 0, 0, NULL});
        pc += 4;
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s input.tk intermediate.tkir output.tko\n", argv[0]);
        return 1;
    }

    Program p = {0};
    LabelTable labels = {0};

    buildFirstPass(argv[1], &p, &labels);

    freeLabels(&labels);
    for (size_t i = 0; i < p.n; i++)
    {
        free(p.a[i].text);
        free(p.a[i].label);
    }
    free(p.a);
    return 0;
}
