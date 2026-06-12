#pragma once
#include <cstdio>
#include <cstring>

// -----------------------------------------------------------------
// Minimal box-drawing UI helpers.
// All boxes are BOX_W characters wide (including the two side bars).
// Use ASCII '+','-','|' so no codepage issues arise on any terminal.
// -----------------------------------------------------------------
static const int BOX_W = 61; // total width incl. side bars

// Prints BOX_W '-' characters padded with '+' corners and a title.
//   BoxTop("")      ->  +-----...-----+
//   BoxTop("Foo")   ->  +- Foo -------+
static inline void BoxTop(const char* title = "")
{
    char line[BOX_W + 4] = {};
    int inner = BOX_W - 2;          // space between the two '+'
    int tlen  = (int)strlen(title);
    int pos   = 0;
    line[pos++] = '+';
    if (tlen > 0) {
        line[pos++] = '-';
        line[pos++] = ' ';
        for (int i = 0; i < tlen && pos < BOX_W - 1; i++)
            line[pos++] = title[i];
        line[pos++] = ' ';
    }
    while (pos < BOX_W - 1) line[pos++] = '-';
    line[pos++] = '+';
    line[pos]   = '\0';
    puts(line);
}

// Same as BoxTop but uses '+' on the left (section divider inside box).
static inline void BoxMid(const char* title = "")
{
    char line[BOX_W + 4] = {};
    int pos = 0;
    line[pos++] = '+';
    if (strlen(title) > 0) {
        line[pos++] = '-';
        line[pos++] = ' ';
        for (int i = 0; title[i] && pos < BOX_W - 1; i++)
            line[pos++] = title[i];
        line[pos++] = ' ';
    }
    while (pos < BOX_W - 1) line[pos++] = '-';
    line[pos++] = '+';
    line[pos]   = '\0';
    puts(line);
}

static inline void BoxBot()
{
    char line[BOX_W + 4] = {};
    line[0] = '+';
    for (int i = 1; i < BOX_W - 1; i++) line[i] = '-';
    line[BOX_W - 1] = '+';
    line[BOX_W]     = '\0';
    puts(line);
}

// Prints a content row, auto-padding to fill the box.
static inline void BoxRow(const char* content)
{
    int inner = BOX_W - 2;
    int clen  = (int)strlen(content);
    printf("|%s", content);
    int pad = inner - clen;
    for (int i = 0; i < pad; i++) putchar(' ');
    puts("|");
}

// Compact status bar — reprinted after every command.
static inline void PrintStatus(const char* src, const char* tgt,
                                unsigned long long linkVA  = 0,
                                unsigned long long linkVPN = 0)
{
    char buf[BOX_W] = {};
    if (linkVA && linkVPN)
        snprintf(buf, sizeof(buf), "  src:%-14s tgt:%-14s VA:0x%llX VPN:0x%llX",
                 src ? src : "?", tgt ? tgt : "?", linkVA, linkVPN);
    else
        snprintf(buf, sizeof(buf), "  src: %-20s  tgt: %s",
                 src ? src : "not set", tgt ? tgt : "not set");
    BoxMid("Status");
    BoxRow(buf);
    BoxBot();
}
