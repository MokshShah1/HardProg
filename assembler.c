#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define BASE_ADDR 0x1000ULL

void die(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    exit(1);
}

void dief(const char *fmt, const char *arg)
{
    fprintf(stderr, "Error: ");
    fprintf(stderr, fmt, arg);
    fprintf(stderr, "\n");
    exit(1);
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    if (!p)
        die("out of memory");
    memcpy(p, s, n + 1);
    return p;
}

void rstrip(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || isspace((unsigned char)s[n - 1])))
    {
        s[n - 1] = '\0';
        n--;
    }
}

const char *skip_ws(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return s;
}

bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

void write_u32_le(FILE *f, uint32_t x)
{
    uint8_t b[4];
    b[0] = (uint8_t)(x & 0xFF);
    b[1] = (uint8_t)((x >> 8) & 0xFF);
    b[2] = (uint8_t)((x >> 16) & 0xFF);
    b[3] = (uint8_t)((x >> 24) & 0xFF);
    if (fwrite(b, 1, 4, f) != 4)
        die("failed writing output");
}

void write_u64_le(FILE *f, uint64_t x)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)((x >> (8 * i)) & 0xFF);
    if (fwrite(b, 1, 8, f) != 8)
        die("failed writing output");
}

bool is_ident_start(char c)
{
    return isalpha((unsigned char)c) || c == '_' || c == '.';
}

bool is_ident_char(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '.';
}

int parse_reg(const char *tok)
{
    if (!tok || (tok[0] != 'r' && tok[0] != 'R'))
        return -1;
    char *end = NULL;
    long v = strtol(tok + 1, &end, 10);
    if (!end || *end != '\0')
        return -1;
    if (v < 0 || v > 31)
        return -1;
    return (int)v;
}

bool parse_u64(const char *tok, uint64_t *out)
{
    if (!tok || !*tok)
        return false;
    // FIX: Reject negative numbers for unsigned parsing
    if (tok[0] == '-')
        return false;

    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(tok, &end, 0);
    if (errno != 0)
        return false;
    if (!end || *end != '\0')
        return false;
    *out = (uint64_t)v;
    return true;
}

bool parse_i12(const char *tok, int32_t *out)
{
    if (!tok || !*tok)
        return false;
    char *end = NULL;
    errno = 0;
    long v = strtol(tok, &end, 0);
    if (errno != 0)
        return false;
    if (!end || *end != '\0')
        return false;
    if (v < -2048 || v > 2047)
        return false;
    *out = (int32_t)v;
    return true;
}

bool parse_u12(const char *tok, uint32_t *out)
{
    uint64_t v;
    if (!parse_u64(tok, &v))
        return false;
    if (v > 0xFFFULL)
        return false;
    *out = (uint32_t)v;
    return true;
}

char *trim_copy(const char *s)
{
    s = skip_ws(s);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        n--;
    char *out = (char *)malloc(n + 1);
    if (!out)
        die("out of memory");
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

typedef struct
{
    char **toks;
    int nt;
} Tokens;

void tokens_free(Tokens *t)
{
    for (int i = 0; i < t->nt; i++)
        free(t->toks[i]);
    free(t->toks);
    t->toks = NULL;
    t->nt = 0;
}

Tokens tokenize(const char *line)
{
    Tokens t = {0};
    size_t cap = 8;
    t.toks = (char **)malloc(sizeof(char *) * cap);
    if (!t.toks)
        die("out of memory");

    const char *p = line;
    while (*p)
    {
        while (*p && (isspace((unsigned char)*p) || *p == ','))
            p++;
        if (!*p)
            break;

        const char *start = p;
        while (*p && !isspace((unsigned char)*p) && *p != ',')
            p++;
        size_t len = (size_t)(p - start);
        char *tok = (char *)malloc(len + 1);
        if (!tok)
            die("out of memory");
        memcpy(tok, start, len);
        tok[len] = '\0';

        if (t.nt == (int)cap)
        {
            cap *= 2;
            t.toks = (char **)realloc(t.toks, sizeof(char *) * cap);
            if (!t.toks)
                die("out of memory");
        }
        t.toks[t.nt++] = tok;
    }
    return t;
}

typedef enum
{
    SEC_NONE,
    SEC_CODE,
    SEC_DATA
} Section;
typedef enum
{
    ITEM_INSTR,
    ITEM_DATA
} ItemKind;

typedef struct
{
    ItemKind kind;
    uint64_t addr;
    char *instr;
    uint64_t data;
} Item;

typedef struct
{
    Item *v;
    size_t n, cap;
} ItemVec;

void items_push(ItemVec *a, Item it)
{
    if (a->n == a->cap)
    {
        a->cap = a->cap ? a->cap * 2 : 64;
        a->v = (Item *)realloc(a->v, a->cap * sizeof(Item));
        if (!a->v)
            die("out of memory");
    }
    a->v[a->n++] = it;
}

typedef struct
{
    char *name;
    uint64_t addr;
} Label;

typedef struct
{
    Label *v;
    size_t n, cap;
} LabelVec;

void labels_put(LabelVec *m, const char *name, uint64_t addr)
{
    for (const char *p = name; *p; p++)
    {
        if (isspace((unsigned char)*p))
        {
            die("label cannot contain spaces");
        }
    }

    if (strlen(name) > 255)
    {
        die("label name too long (max 255 characters)");
    }

    for (size_t i = 0; i < m->n; i++)
    {
        if (strcmp(m->v[i].name, name) == 0)
        {
            dief("duplicate label: %s", name);
        }
    }
    if (m->n == m->cap)
    {
        m->cap = m->cap ? m->cap * 2 : 64;
        m->v = (Label *)realloc(m->v, m->cap * sizeof(Label));
        if (!m->v)
            die("out of memory");
    }
    m->v[m->n].name = xstrdup(name);
    m->v[m->n].addr = addr;
    m->n++;
}

bool labels_get(const LabelVec *m, const char *name, uint64_t *out)
{
    for (size_t i = 0; i < m->n; i++)
    {
        if (strcmp(m->v[i].name, name) == 0)
        {
            *out = m->v[i].addr;
            return true;
        }
    }
    return false;
}

void labels_free(LabelVec *m)
{
    for (size_t i = 0; i < m->n; i++)
        free(m->v[i].name);
    free(m->v);
    m->v = NULL;
    m->n = m->cap = 0;
}

void items_free(ItemVec *a)
{
    for (size_t i = 0; i < a->n; i++)
    {
        free(a->v[i].instr);
    }
    free(a->v);
    a->v = NULL;
    a->n = a->cap = 0;
}

void emit_ld_macro(ItemVec *items, uint64_t *pc, int rd, uint64_t imm)
{
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "xor r%d, r%d, r%d", rd, rd, rd);
        Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
        items_push(items, it);
        *pc += 4;
    }

    {
        char buf[64];
        uint64_t val = (imm >> 52) & 0xFFF;
        snprintf(buf, sizeof(buf), "addi r%d, %llu", rd, (unsigned long long)val);
        Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
        items_push(items, it);
        *pc += 4;
    }

    {
        Item s = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        char b[64];
        snprintf(b, sizeof(b), "shftli r%d, 12", rd);
        s.instr = xstrdup(b);
        items_push(items, s);
        *pc += 4;

        Item a = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        uint64_t val = (imm >> 40) & 0xFFF;
        snprintf(b, sizeof(b), "addi r%d, %llu", rd, (unsigned long long)val);
        a.instr = xstrdup(b);
        items_push(items, a);
        *pc += 4;
    }

    {
        Item s = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        char b[64];
        snprintf(b, sizeof(b), "shftli r%d, 12", rd);
        s.instr = xstrdup(b);
        items_push(items, s);
        *pc += 4;

        Item a = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        uint64_t val = (imm >> 28) & 0xFFF;
        snprintf(b, sizeof(b), "addi r%d, %llu", rd, (unsigned long long)val);
        a.instr = xstrdup(b);
        items_push(items, a);
        *pc += 4;
    }

    {
        Item s = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        char b[64];
        snprintf(b, sizeof(b), "shftli r%d, 12", rd);
        s.instr = xstrdup(b);
        items_push(items, s);
        *pc += 4;

        Item a = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        uint64_t val = (imm >> 16) & 0xFFF;
        snprintf(b, sizeof(b), "addi r%d, %llu", rd, (unsigned long long)val);
        a.instr = xstrdup(b);
        items_push(items, a);
        *pc += 4;
    }

    {
        Item s = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        char b[64];
        snprintf(b, sizeof(b), "shftli r%d, 12", rd);
        s.instr = xstrdup(b);
        items_push(items, s);
        *pc += 4;

        Item a = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        uint64_t val = (imm >> 4) & 0xFFF;
        snprintf(b, sizeof(b), "addi r%d, %llu", rd, (unsigned long long)val);
        a.instr = xstrdup(b);
        items_push(items, a);
        *pc += 4;
    }

    {
        Item s = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        char b[64];
        snprintf(b, sizeof(b), "shftli r%d, 4", rd);
        s.instr = xstrdup(b);
        items_push(items, s);
        *pc += 4;

        Item a = {.kind = ITEM_INSTR, .addr = *pc, .instr = NULL};
        uint64_t val = imm & 0xF;
        snprintf(b, sizeof(b), "addi r%d, %llu", rd, (unsigned long long)val);
        a.instr = xstrdup(b);
        items_push(items, a);
        *pc += 4;
    }
}

void emit_clr_macro(ItemVec *items, uint64_t *pc, int rd)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "xor r%d, r%d, r%d", rd, rd, rd);
    Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
    items_push(items, it);
    *pc += 4;
}

void emit_halt_macro(ItemVec *items, uint64_t *pc)
{
    Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup("priv r0, r0, r0, 0")};
    items_push(items, it);
    *pc += 4;
}

void emit_in_macro(ItemVec *items, uint64_t *pc, int rd, int rs)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "priv r%d, r%d, r0, 3", rd, rs);
    Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
    items_push(items, it);
    *pc += 4;
}

void emit_out_macro(ItemVec *items, uint64_t *pc, int rd, int rs)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "priv r%d, r%d, r0, 4", rd, rs);
    Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
    items_push(items, it);
    *pc += 4;
}

void emit_push_macro(ItemVec *items, uint64_t *pc, int rd)
{
    {
        Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup("subi r31, 8")};
        items_push(items, it);
        *pc += 4;
    }
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "mov (r31)(0), r%d", rd);
        Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
        items_push(items, it);
        *pc += 4;
    }
}

void emit_pop_macro(ItemVec *items, uint64_t *pc, int rd)
{
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "mov r%d, (r31)(0)", rd);
        Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup(buf)};
        items_push(items, it);
        *pc += 4;
    }
    {
        Item it = {.kind = ITEM_INSTR, .addr = *pc, .instr = xstrdup("addi r31, 8")};
        items_push(items, it);
        *pc += 4;
    }
}

const char *label_ref(const char *tok)
{
    if (tok && tok[0] == ':' && tok[1] != '\0')
        return tok + 1;
    return NULL;
}

char *replace_label_refs(const char *instr_line, const LabelVec *labels)
{
    Tokens t = tokenize(instr_line);
    if (t.nt == 0)
    {
        tokens_free(&t);
        return xstrdup(instr_line);
    }

    size_t cap = 256;
    char *out = (char *)malloc(cap);
    if (!out)
        die("out of memory");
    out[0] = '\0';

    for (int i = 0; i < t.nt; i++)
    {
        const char *lr = label_ref(t.toks[i]);
        char buf[64];
        const char *piece = t.toks[i];
        if (lr)
        {
            uint64_t addr;
            if (!labels_get(labels, lr, &addr))
            {
                dief("undefined label reference: %s", lr);
            }
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)addr);
            piece = buf;
        }

        size_t need = strlen(out) + strlen(piece) + 2;
        if (need > cap)
        {
            while (need > cap)
                cap *= 2;
            out = (char *)realloc(out, cap);
            if (!out)
                die("out of memory");
        }
        if (i)
            strcat(out, " ");
        strcat(out, piece);
    }

    tokens_free(&t);
    return out;
}

char *parse_label_def(const char *line)
{
    const char *p = skip_ws(line);
    if (*p != ':')
        die("internal: expected ':' label");
    p++;
    p = skip_ws(p);
    if (!is_ident_start(*p) && *p != '_')
        die("malformed label name");
    const char *start = p;
    while (*p && is_ident_char(*p))
        p++;
    size_t len = (size_t)(p - start);
    char *name = (char *)malloc(len + 1);
    if (!name)
        die("out of memory");
    memcpy(name, start, len);
    name[len] = '\0';

    // FIX: Check for garbage after label definition
    p = skip_ws(p);
    if (*p != '\0' && *p != ';')
    {
        die("garbage after label definition");
    }

    return name;
}

void pass1_build(const char *in_path, ItemVec *items, LabelVec *labels)
{
    FILE *f = fopen(in_path, "r");
    if (!f)
        dief("cannot open input file: %s", in_path);

    Section sec = SEC_NONE;
    uint64_t pc = BASE_ADDR;
    bool has_code_directive = false;

    char line[4096];
    while (fgets(line, sizeof(line), f))
    {
        rstrip(line);
        const char *p = line;

        if (*p == '\0')
            continue;
        if (*p == ';')
            continue;

        if (starts_with(p, ".code"))
        {
            sec = SEC_CODE;
            has_code_directive = true;
            continue;
        }
        if (starts_with(p, ".data"))
        {
            sec = SEC_DATA;
            continue;
        }

        if (*p == ':')
        {
            char *name = parse_label_def(p);
            labels_put(labels, name, pc);
            free(name);
            continue;
        }

        if (*p != '\t')
        {
            die("code/data line must start with tab character");
        }

        if (sec == SEC_NONE)
        {
            die("code/data line before any .code or .data directive");
        }

        while (*p == '\t')
            p++;
        p = skip_ws(p);
        if (*p == '\0')
            continue;

        if (sec == SEC_DATA)
        {
            uint64_t v;
            if (!parse_u64(p, &v))
            {
                die("malformed data item (expected 64-bit unsigned integer)");
            }
            Item it = {.kind = ITEM_DATA, .addr = pc, .data = v, .instr = NULL};
            items_push(items, it);
            pc += 8;
            continue;
        }

        Tokens t = tokenize(p);
        if (t.nt == 0)
        {
            tokens_free(&t);
            continue;
        }

        for (char *c = t.toks[0]; *c; c++)
            *c = (char)tolower((unsigned char)*c);

        const char *mn = t.toks[0];

        if (strcmp(mn, "clr") == 0)
        {
            if (t.nt != 2)
                die("clr macro expects: clr rd");
            int rd = parse_reg(t.toks[1]);
            if (rd < 0)
                die("clr: invalid register");
            emit_clr_macro(items, &pc, rd);
            tokens_free(&t);
            continue;
        }
        if (strcmp(mn, "halt") == 0)
        {
            if (t.nt != 1)
                die("halt macro expects: halt");
            emit_halt_macro(items, &pc);
            tokens_free(&t);
            continue;
        }
        if (strcmp(mn, "in") == 0)
        {
            if (t.nt != 3)
                die("in macro expects: in rd, rs");
            int rd = parse_reg(t.toks[1]);
            int rs = parse_reg(t.toks[2]);
            if (rd < 0 || rs < 0)
                die("in: invalid register");
            emit_in_macro(items, &pc, rd, rs);
            tokens_free(&t);
            continue;
        }
        if (strcmp(mn, "out") == 0)
        {
            if (t.nt != 3)
                die("out macro expects: out rd, rs");
            int rd = parse_reg(t.toks[1]);
            int rs = parse_reg(t.toks[2]);
            if (rd < 0 || rs < 0)
                die("out: invalid register");
            emit_out_macro(items, &pc, rd, rs);
            tokens_free(&t);
            continue;
        }
        if (strcmp(mn, "push") == 0)
        {
            if (t.nt != 2)
                die("push macro expects: push rd");
            int rd = parse_reg(t.toks[1]);
            if (rd < 0)
                die("push: invalid register");
            emit_push_macro(items, &pc, rd);
            tokens_free(&t);
            continue;
        }
        if (strcmp(mn, "pop") == 0)
        {
            if (t.nt != 2)
                die("pop macro expects: pop rd");
            int rd = parse_reg(t.toks[1]);
            if (rd < 0)
                die("pop: invalid register");
            emit_pop_macro(items, &pc, rd);
            tokens_free(&t);
            continue;
        }
        if (strcmp(mn, "ld") == 0)
        {
            if (t.nt != 3)
                die("ld macro expects: ld rd, immOrLabel");
            int rd = parse_reg(t.toks[1]);
            if (rd < 0)
                die("ld: invalid register");

            const char *lr = label_ref(t.toks[2]);
            if (lr)
            {
                char buf[256];
                snprintf(buf, sizeof(buf), "__ldresolve r%d, :%s", rd, lr);
                Item it = {.kind = ITEM_INSTR, .addr = pc, .instr = xstrdup(buf)};
                items_push(items, it);
                pc += 4;
            }
            else
            {
                uint64_t imm;
                if (!parse_u64(t.toks[2], &imm))
                    die("ld: invalid literal");
                emit_ld_macro(items, &pc, rd, imm);
            }
            tokens_free(&t);
            continue;
        }

        Item it = {.kind = ITEM_INSTR, .addr = pc, .instr = trim_copy(p)};
        items_push(items, it);
        pc += 4;

        tokens_free(&t);
    }

    fclose(f);

    if (!has_code_directive)
    {
        die("program must have at least one .code directive");
    }
}

ItemVec rebuild_with_label_resolution(const ItemVec *items_in, const LabelVec *labels)
{
    ItemVec out = {0};
    uint64_t pc = BASE_ADDR;

    for (size_t i = 0; i < items_in->n; i++)
    {
        const Item *cur = &items_in->v[i];

        if (cur->kind == ITEM_DATA)
        {
            Item it = *cur;
            it.addr = pc;
            it.instr = NULL;
            items_push(&out, it);
            pc += 8;
            continue;
        }

        if (!cur->instr)
            die("internal: instr item missing text");

        if (starts_with(cur->instr, "__ldresolve"))
        {
            Tokens t = tokenize(cur->instr);
            if (t.nt != 3)
                die("malformed __ldresolve");
            int rd = parse_reg(t.toks[1]);
            if (rd < 0)
                die("malformed __ldresolve rd");
            const char *lr = label_ref(t.toks[2]);
            if (!lr)
                die("malformed __ldresolve label");

            uint64_t addr;
            if (!labels_get(labels, lr, &addr))
            {
                dief("ld: undefined label: %s", lr);
            }

            emit_ld_macro(&out, &pc, rd, addr);

            tokens_free(&t);
            continue;
        }

        char *resolved = replace_label_refs(cur->instr, labels);
        Item it = {.kind = ITEM_INSTR, .addr = pc, .instr = resolved};
        items_push(&out, it);
        pc += 4;
    }
    return out;
}

uint32_t pack_rtype(uint32_t op, uint32_t rd, uint32_t rs, uint32_t rt)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | ((rt & 0x1F) << 12);
}

uint32_t pack_itype(uint32_t op, uint32_t rd, uint32_t rs, uint32_t imm12)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | (imm12 & 0xFFF);
}

uint32_t pack_priv(uint32_t op, uint32_t rd, uint32_t rs, uint32_t rt, uint32_t imm12)
{
    return ((op & 0x1F) << 27) | ((rd & 0x1F) << 22) | ((rs & 0x1F) << 17) | ((rt & 0x1F) << 12) | (imm12 & 0xFFF);
}

uint32_t encode_one(const char *instr)
{
    Tokens t = tokenize(instr);
    if (t.nt == 0)
    {
        tokens_free(&t);
        die("empty instruction");
    }

    for (char *c = t.toks[0]; *c; c++)
        *c = (char)tolower((unsigned char)*c);
    const char *mn = t.toks[0];

    int rd = -1, rs = -1, rt = -1;
    uint32_t u12 = 0;
    int32_t i12 = 0;

    if (strcmp(mn, "and") == 0 || strcmp(mn, "or") == 0 || strcmp(mn, "xor") == 0 ||
        strcmp(mn, "add") == 0 || strcmp(mn, "sub") == 0 || strcmp(mn, "mul") == 0 || strcmp(mn, "div") == 0 ||
        strcmp(mn, "addf") == 0 || strcmp(mn, "subf") == 0 || strcmp(mn, "mulf") == 0 || strcmp(mn, "divf") == 0 ||
        strcmp(mn, "shftr") == 0 || strcmp(mn, "shftl") == 0)
    {

        if (t.nt != 4)
            die("R-type expects 3 registers");
        rd = parse_reg(t.toks[1]);
        rs = parse_reg(t.toks[2]);
        rt = parse_reg(t.toks[3]);
        if (rd < 0 || rs < 0 || rt < 0)
            die("invalid register");

        uint32_t op;
        if (strcmp(mn, "and") == 0)
            op = 0x0;
        else if (strcmp(mn, "or") == 0)
            op = 0x1;
        else if (strcmp(mn, "xor") == 0)
            op = 0x2;
        else if (strcmp(mn, "shftr") == 0)
            op = 0x4;
        else if (strcmp(mn, "shftl") == 0)
            op = 0x6;
        else if (strcmp(mn, "addf") == 0)
            op = 0x14;
        else if (strcmp(mn, "subf") == 0)
            op = 0x15;
        else if (strcmp(mn, "mulf") == 0)
            op = 0x16;
        else if (strcmp(mn, "divf") == 0)
            op = 0x17;
        else if (strcmp(mn, "add") == 0)
            op = 0x18;
        else if (strcmp(mn, "sub") == 0)
            op = 0x1a;
        else if (strcmp(mn, "mul") == 0)
            op = 0x1c;
        else if (strcmp(mn, "div") == 0)
            op = 0x1d;
        else
            die("unknown r-type");
        tokens_free(&t);
        return pack_rtype(op, (uint32_t)rd, (uint32_t)rs, (uint32_t)rt);
    }

    if (strcmp(mn, "not") == 0)
    {
        if (t.nt != 3)
            die("not expects 2 registers");
        rd = parse_reg(t.toks[1]);
        rs = parse_reg(t.toks[2]);
        if (rd < 0 || rs < 0)
            die("invalid register");
        tokens_free(&t);
        return pack_rtype(0x3, (uint32_t)rd, (uint32_t)rs, 0);
    }

    if (strcmp(mn, "addi") == 0 || strcmp(mn, "subi") == 0 || strcmp(mn, "shftri") == 0 || strcmp(mn, "shftli") == 0)
    {
        if (t.nt != 3)
            die("I-type expects rd, imm");
        rd = parse_reg(t.toks[1]);
        if (rd < 0)
            die("invalid register");
        if (!parse_u12(t.toks[2], &u12))
            die("immediate must be 0..4095");
        uint32_t op;
        if (strcmp(mn, "addi") == 0)
            op = 0x19;
        else if (strcmp(mn, "subi") == 0)
            op = 0x1b;
        else if (strcmp(mn, "shftri") == 0)
            op = 0x5;
        else
            op = 0x7;
        tokens_free(&t);
        return pack_itype(op, (uint32_t)rd, 0, u12);
    }

    if (strcmp(mn, "br") == 0)
    {
        if (t.nt != 2)
            die("br expects rd");
        rd = parse_reg(t.toks[1]);
        if (rd < 0)
            die("invalid register");
        tokens_free(&t);
        return pack_rtype(0x8, (uint32_t)rd, 0, 0);
    }

    if (strcmp(mn, "brr") == 0)
    {
        if (t.nt != 2)
            die("brr expects rd or imm");
        int r = parse_reg(t.toks[1]);
        if (r >= 0)
        {
            tokens_free(&t);
            return pack_rtype(0x9, (uint32_t)r, 0, 0);
        }
        else
        {
            if (!parse_i12(t.toks[1], &i12))
                die("brr immediate must fit signed 12-bit");
            uint32_t imm12 = (uint32_t)((int32_t)i12 & 0xFFF);
            tokens_free(&t);
            return ((0x0a & 0x1F) << 27) | (imm12 & 0xFFF);
        }
    }

    if (strcmp(mn, "brnz") == 0)
    {
        if (t.nt != 3)
            die("brnz expects rd, rs");
        rd = parse_reg(t.toks[1]);
        rs = parse_reg(t.toks[2]);
        if (rd < 0 || rs < 0)
            die("invalid register");
        tokens_free(&t);
        return pack_rtype(0x0b, (uint32_t)rd, (uint32_t)rs, 0);
    }

    if (strcmp(mn, "call") == 0)
    {
        if (t.nt != 2)
            die("call expects rd");
        rd = parse_reg(t.toks[1]);
        if (rd < 0)
            die("invalid register");
        tokens_free(&t);
        return pack_rtype(0x0c, (uint32_t)rd, 0, 0);
    }

    if (strcmp(mn, "return") == 0)
    {
        if (t.nt != 1)
            die("return expects no operands");
        tokens_free(&t);
        return ((0x0d & 0x1F) << 27);
    }

    if (strcmp(mn, "brgt") == 0)
    {
        if (t.nt != 4)
            die("brgt expects rd, rs, rt");
        rd = parse_reg(t.toks[1]);
        rs = parse_reg(t.toks[2]);
        rt = parse_reg(t.toks[3]);
        if (rd < 0 || rs < 0 || rt < 0)
            die("invalid register");
        tokens_free(&t);
        return pack_rtype(0x0e, (uint32_t)rd, (uint32_t)rs, (uint32_t)rt);
    }

    if (strcmp(mn, "priv") == 0)
    {
        if (t.nt != 5)
            die("priv expects rd, rs, rt, imm");
        rd = parse_reg(t.toks[1]);
        rs = parse_reg(t.toks[2]);
        rt = parse_reg(t.toks[3]);
        if (rd < 0 || rs < 0 || rt < 0)
            die("invalid register");
        if (!parse_u12(t.toks[4], &u12))
            die("priv imm must be 0..4095");
        tokens_free(&t);
        return pack_priv(0x0f, (uint32_t)rd, (uint32_t)rs, (uint32_t)rt, u12);
    }

    if (strcmp(mn, "mov") == 0)
    {
        if (t.nt != 3)
            die("mov expects 2 operands");
        const char *op1 = t.toks[1];
        const char *op2 = t.toks[2];

        if (op1[0] == '(')
        {
            int regA = -1;
            int32_t imm = -9999;

            const char *p = op1;
            if (*p != '(')
                die("mov store: malformed operand");
            p++;
            char regbuf[16] = {0};
            int k = 0;
            while (*p && *p != ')' && k < 15)
                regbuf[k++] = *p++;
            regbuf[k] = '\0';
            if (*p != ')')
                die("mov store: malformed operand");
            p++;
            if (*p != '(')
                die("mov store: expected second ()");
            p++;
            char immbuf[32] = {0};
            k = 0;
            while (*p && *p != ')' && k < 31)
                immbuf[k++] = *p++;
            immbuf[k] = '\0';
            if (*p != ')')
                die("mov store: malformed imm");
            regA = parse_reg(regbuf);
            if (regA < 0)
                die("mov store: invalid base reg");
            if (!parse_i12(immbuf, &imm))
                die("mov store: imm must fit signed 12-bit");
            rs = parse_reg(op2);
            if (rs < 0)
                die("mov store: invalid source reg");
            tokens_free(&t);
            uint32_t imm12 = (uint32_t)((int32_t)imm & 0xFFF);
            return pack_priv(0x13, (uint32_t)regA, (uint32_t)rs, 0, imm12);
        }

        if (op2[0] == '(')
        {
            rd = parse_reg(op1);
            if (rd < 0)
                die("mov load: invalid rd");
            int regA = -1;
            int32_t imm = -9999;
            const char *p = op2;
            if (*p != '(')
                die("mov load: malformed operand");
            p++;
            char regbuf[16] = {0};
            int k = 0;
            while (*p && *p != ')' && k < 15)
                regbuf[k++] = *p++;
            regbuf[k] = '\0';
            if (*p != ')')
                die("mov load: malformed operand");
            p++;
            if (*p != '(')
                die("mov load: expected second ()");
            p++;
            char immbuf[32] = {0};
            k = 0;
            while (*p && *p != ')' && k < 31)
                immbuf[k++] = *p++;
            immbuf[k] = '\0';
            if (*p != ')')
                die("mov load: malformed imm");
            regA = parse_reg(regbuf);
            if (regA < 0)
                die("mov load: invalid base reg");
            if (!parse_i12(immbuf, &imm))
                die("mov load: imm must fit signed 12-bit");
            tokens_free(&t);
            uint32_t imm12 = (uint32_t)((int32_t)imm & 0xFFF);
            return pack_priv(0x10, (uint32_t)rd, (uint32_t)regA, 0, imm12);
        }

        rd = parse_reg(op1);
        if (rd < 0)
            die("mov: invalid rd");
        rs = parse_reg(op2);
        if (rs >= 0)
        {
            tokens_free(&t);
            return pack_rtype(0x11, (uint32_t)rd, (uint32_t)rs, 0);
        }
        else
        {
            if (!parse_u12(op2, &u12))
                die("mov rd, L: L must be 0..4095");
            tokens_free(&t);
            return pack_itype(0x12, (uint32_t)rd, 0, u12);
        }
    }

    tokens_free(&t);
    dief("unknown instruction mnemonic: %s", mn);
    return 0;
}

void write_intermediate(const char *path, const ItemVec *prog)
{
    FILE *f = fopen(path, "w");
    if (!f)
        dief("cannot open intermediate file: %s", path);

    // FIX: Always start with .code to ensure valid output for data-only inputs
    fprintf(f, ".code\n");
    Section last_sec = SEC_CODE;

    for (size_t i = 0; i < prog->n; i++)
    {
        const Item *it = &prog->v[i];

        Section cur_sec = (it->kind == ITEM_DATA) ? SEC_DATA : SEC_CODE;

        if (cur_sec != last_sec)
        {
            if (cur_sec == SEC_CODE)
            {
                fprintf(f, ".code\n");
            }
            else
            {
                fprintf(f, ".data\n");
            }
            last_sec = cur_sec;
        }

        if (it->kind == ITEM_DATA)
        {
            fprintf(f, "\t%llu\n", (unsigned long long)it->data);
        }
        else
        {
            fprintf(f, "\t%s\n", it->instr);
        }
    }

    fclose(f);
}

void write_binary(const char *path, const ItemVec *prog)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        dief("cannot open binary output file: %s", path);

    for (size_t i = 0; i < prog->n; i++)
    {
        const Item *it = &prog->v[i];
        if (it->kind == ITEM_DATA)
        {
            write_u64_le(f, it->data);
        }
        else
        {
            uint32_t bin = encode_one(it->instr);
            write_u32_le(f, bin);
        }
    }

    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s input.tk intermediate.tk output.tko\n", argv[0]);
        return 1;
    }
    const char *in_path = argv[1];
    const char *int_path = argv[2];
    const char *out_path = argv[3];

    ItemVec raw = {0};
    LabelVec labels = {0};

    pass1_build(in_path, &raw, &labels);

    ItemVec prog = rebuild_with_label_resolution(&raw, &labels);

    write_intermediate(int_path, &prog);

    write_binary(out_path, &prog);

    items_free(&raw);
    items_free(&prog);
    labels_free(&labels);

    return 0;
}