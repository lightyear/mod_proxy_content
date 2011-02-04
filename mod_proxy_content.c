/********************************************************************

Copyright (c) 2008-2009 Council of Better Business Bureaus
Author: Steve Madsen <steve@lightyearsoftware.com>

Copyright (c) 2003-9, WebThing Ltd
Author: Nick Kew <nick@webthing.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License  Version 2,
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You can obtain a copy of the GNU General Poblic License Version 2
from http://www.gnu.org/licenses/old-licenses/gpl-2.0.html or
http://apache.webthing.com/COPYING.txt

*********************************************************************/


/*      GO_FASTER

        You can #define GO_FASTER to disable informational logging.
        This disables the ProxyHTMLLogVerbose option altogether.

        Default is to leave it undefined, and enable verbose logging
        as a configuration option.  Binaries are supplied with verbose
        logging enabled.
*/

#ifdef GO_FASTER
#define VERBOSE(verbose, x)
#define VERBOSEB(verbose, x)
#else
#define VERBOSE(verbose, x) if (verbose) x
#define VERBOSEB(verbose, x) if (verbose) {x}
#endif

#ifdef DEVELOPER
#define DEBUG(verbose, x) if (verbose) x
#else
#define DEBUG(verbose, x)
#endif

#define VERSION_STRING "proxy_content/1.0"

#include <ctype.h>

/* libxml2 */
#include <libxml/HTMLparser.h>

/* apache */
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include <apr_strmatch.h>
#include <apr_xlate.h>

/* To support Apache 2.1/2.2, we need the ap_ forms of the
 * regexp stuff, and they're now used in the code.
 * To support 2.0 in the same compile, * we #define the
 * AP_ versions if necessary.
 */
#ifndef AP_REG_ICASE
/* it's 2.0, so we #define the ap_ versions */
#define ap_regex_t regex_t
#define ap_regmatch_t regmatch_t
#define AP_REG_EXTENDED REG_EXTENDED
#define AP_REG_ICASE REG_ICASE
#define AP_REG_NOSUB REG_NOSUB
#define AP_REG_NEWLINE REG_NEWLINE
#define APACHE20
#define ap_register_output_filter_protocol(a,b,c,d,e) ap_register_output_filter(a,b,c,d)
#else
#define APACHE22
#endif

module AP_MODULE_DECLARE_DATA proxy_content_module;

#define M_HTML                  0x01
#define M_EVENTS                0x02
#define M_CDATA                 0x04
#define M_REGEX                 0x08
#define M_ATSTART               0x10
#define M_ATEND                 0x20
#define M_LAST                  0x40
#define M_NOTLAST               0x80
#define M_INTERPOLATE_TO        0x100
#define M_INTERPOLATE_FROM      0x200
#define M_STYLES                0x400

typedef struct
{
    const char *val;
} tattr;

typedef struct
{
    unsigned int start;
    unsigned int end;
} meta;

typedef struct
{
    const char *env;
    const char *val;
    int rel;
} rewritecond;

typedef struct urlmap
{
    struct urlmap *next;
    unsigned int flags;
    unsigned int regflags;
    struct
    {
        const char *c;
        ap_regex_t *r;
        ap_regex_t *css_r;
        ap_regex_t *js_r;
    } from;
    const char *to;
    const char *to_css;
    const char *to_js;
    rewritecond *cond;
} urlmap;

#define EXTFIX_STYLES  0x1
#define EXTFIX_SCRIPTS 0x2

typedef struct
{
    urlmap *map;
    const char *doctype;
    const char *etag;
    unsigned int flags;
    size_t bufsz;
    apr_hash_t *links;
    apr_array_header_t *events;
    apr_array_header_t *skipto;
    xmlCharEncoding default_encoding;
    const char *charset_out;
    unsigned int extfix;
    int metafix;
    int strip_comments;
    int interp;
    int verbose;
    unsigned int max_url_length;
} proxy_content_conf;

typedef struct
{
    apr_xlate_t *convset;
    char *buf;
    apr_size_t bytes;
} conv_t;

typedef enum { CONTENT_TYPE_HTML, CONTENT_TYPE_CSS, CONTENT_TYPE_JS } content_type_t;

typedef struct
{
    ap_filter_t *f;
    proxy_content_conf *cfg;
    htmlParserCtxtPtr parser;
    apr_bucket_brigade *bb;
    char *buf;
    size_t offset;
    size_t avail;
    conv_t *conv_in;
    conv_t *conv_out;
    const char *encoding;
    urlmap *map;
    content_type_t content_type;
    apr_bucket_brigade *saved_buckets;
    void **matched_bucket;
    unsigned int matched_size;
} filter_ctxt;


#define NORM_LC 0x1
#define NORM_MSSLASH 0x2
#define NORM_RESET 0x4
static htmlSAXHandler sax;

typedef enum { ATTR_IGNORE, ATTR_URI, ATTR_EVENT, ATTR_STYLE } rewrite_t;

static const char *const fpi_html =
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n";
static const char *const fpi_html_legacy =
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n";
static const char *const fpi_xhtml =
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n";
static const char *const fpi_xhtml_legacy =
    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n";
static const char *const html_etag = ">";
static const char *const xhtml_etag = " />";

/*#define DEFAULT_DOCTYPE fpi_html */
static const char *const DEFAULT_DOCTYPE = "";

#define DEFAULT_ETAG html_etag

static void
normalise(unsigned int flags, char *str)
{
    char *p;

    if (flags & NORM_LC)
        for (p = str; *p; ++p)
            if (isupper(*p))
                *p = tolower(*p);

    if (flags & NORM_MSSLASH)
        for (p = ap_strchr(str, '\\'); p; p = ap_strchr(p + 1, '\\'))
            *p = '/';
}

static void
consume_buffer(filter_ctxt * ctx, const char *inbuf, int bytes, int flag)
{
    apr_status_t rv;
    apr_size_t insz;
    char *buf;
    
/*    DEBUG(ctx->cfg->verbose,
          ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                        "consume \"%s\"", apr_pstrndup(ctx->f->r->pool, inbuf, bytes))); */
          
    if (ctx->conv_in == NULL)
    {
        /* just feed it to libxml2 */
        htmlParseChunk(ctx->parser, inbuf, bytes, flag);
        return;
    }
    if (ctx->conv_in->bytes > 0)
    {
        /* FIXME: make this a reusable buf? */
        buf = apr_palloc(ctx->f->r->pool, ctx->conv_in->bytes + bytes);
        memcpy(buf, ctx->conv_in->buf, ctx->conv_in->bytes);
        memcpy(buf + ctx->conv_in->bytes, inbuf, bytes);
        bytes += ctx->conv_in->bytes;
        ctx->conv_in->bytes = 0;
    }
    else
    {
        buf = (char *) inbuf;
    }
    insz = bytes;
    while (insz > 0)
    {
        char outbuf[4096];
        apr_size_t outsz = 4096;

        rv = apr_xlate_conv_buffer(ctx->conv_in->convset,
                                   buf + (bytes - insz), &insz, outbuf, &outsz);
        htmlParseChunk(ctx->parser, outbuf, 4096 - outsz, flag);
        switch (rv)
        {
            case APR_SUCCESS:
                continue;
            case APR_EINCOMPLETE:
                if (insz < 32)
                {               /* save dangling byte(s) and return */
                    ctx->conv_in->bytes = insz;
                    ctx->conv_in->buf = (buf != inbuf) ? buf + (bytes - insz)
                        : apr_pmemdup(ctx->f->r->pool, buf + (bytes - insz), insz);
                    return;
                }
                else
                {               /*OK, maybe 4096 wasn't big enough, and ended mid-char */
                    continue;
                }
            case APR_EINVAL:   /* try skipping one bad byte */
                VERBOSE(ctx->cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->f->r,
                                      "Skipping invalid byte in input stream!"));
                --insz;
                continue;
            default:
                /* Erk!  What's this? Bail out and eat the buf raw
                 * if libxml2 will accept it!
                 */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, ctx->f->r,
                              "Failed to convert input; trying it raw");
                htmlParseChunk(ctx->parser, buf + (bytes - insz), insz, flag);
                ctx->conv_in = NULL;    /* don't try converting any more */
                return;
        }
    }
}

static void
AP_fwrite(filter_ctxt * ctx, const char *inbuf, int bytes, int flush)
{
    /* convert charset if necessary, and output */
    char *buf;
    apr_status_t rv;
    apr_size_t insz;

    if (ctx->conv_out == NULL)
    {
        ap_fwrite(ctx->f->next, ctx->bb, inbuf, bytes);
        return;
    }
    if (ctx->conv_out->bytes > 0)
    {
        /* FIXME: make this a reusable buf? */
        buf = apr_palloc(ctx->f->r->pool, ctx->conv_out->bytes + bytes);
        memcpy(buf, ctx->conv_out->buf, ctx->conv_out->bytes);
        memcpy(buf + ctx->conv_out->bytes, inbuf, bytes);
        bytes += ctx->conv_out->bytes;
        ctx->conv_out->bytes = 0;
    }
    else
    {
        buf = (char *) inbuf;
    }
    insz = bytes;
    while (insz > 0)
    {
        char outbuf[2048];
        apr_size_t outsz = 2048;

        rv = apr_xlate_conv_buffer(ctx->conv_out->convset,
                                   buf + (bytes - insz), &insz, outbuf, &outsz);
        ap_fwrite(ctx->f->next, ctx->bb, outbuf, 2048 - outsz);
        switch (rv)
        {
            case APR_SUCCESS:
                continue;
            case APR_EINCOMPLETE:      /* save dangling byte(s) and return */
                /* but if we need to flush, just abandon them */
                if (flush)
                {               /* if we're flushing, this must be complete */
                    /* so this is an error */
                    VERBOSE(ctx->cfg->verbose,
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->f->r,
                            "Skipping invalid byte in output stream!"));
                }
                else
                {
                    ctx->conv_out->bytes = insz;
                    ctx->conv_out->buf = (buf != inbuf) ? buf + (bytes - insz)
                        : apr_pmemdup(ctx->f->r->pool, buf + (bytes - insz), insz);
                }
                break;
            case APR_EINVAL:   /* try skipping one bad byte */
                VERBOSE(ctx->cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->f->r,
                        "Skipping invalid byte in output stream!"));
                --insz;
                continue;
            default:
                /* Erk!  What's this? Bail out and pass the buf raw
                 * if libxml2 will accept it!
                 */
                VERBOSE(ctx->cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, ctx->f->r,
                        "Failed to convert output; sending UTF-8"));
                ap_fwrite(ctx->f->next, ctx->bb, buf + (bytes - insz), insz);
                break;
        }
    }
}

/* This is always utf-8 on entry.  We can convert charset within FLUSH */
#define FLUSH AP_fwrite(ctx, (chars+begin), (i-begin), 0) ; begin = i+1

static void
pcharacters(void *ctxt, const xmlChar * uchars, int length)
{
    const char *chars = (const char *) uchars;
    filter_ctxt *ctx = (filter_ctxt *) ctxt;
    int i;
    int begin;

    for (begin = i = 0; i < length; i++)
    {
        switch (chars[i])
        {
            case '&':
                FLUSH;
                ap_fputs(ctx->f->next, ctx->bb, "&amp;");
                break;
            case '<':
                FLUSH;
                ap_fputs(ctx->f->next, ctx->bb, "&lt;");
                break;
            case '>':
                FLUSH;
                ap_fputs(ctx->f->next, ctx->bb, "&gt;");
                break;
            case '"':
                FLUSH;
                ap_fputs(ctx->f->next, ctx->bb, "&quot;");
                break;
            default:
                break;
        }
    }
    FLUSH;
}

static void
preserve(filter_ctxt * ctx, const size_t len)
{
    char *newbuf;

    if (len <= (ctx->avail - ctx->offset))
        return;
    else
        while (len > (ctx->avail - ctx->offset))
            ctx->avail += ctx->cfg->bufsz;

    newbuf = realloc(ctx->buf, ctx->avail);
    if (newbuf != ctx->buf)
    {
        if (ctx->buf)
            apr_pool_cleanup_kill(ctx->f->r->pool, ctx->buf, (int(*)(void *))free);
        apr_pool_cleanup_register(ctx->f->r->pool, newbuf, (int(*)(void *))free, apr_pool_cleanup_null);
        ctx->buf = newbuf;
    }
}

static void
pappend(filter_ctxt * ctx, const char *buf, const size_t len)
{
    preserve(ctx, len);
    memcpy(ctx->buf + ctx->offset, buf, len);
    ctx->offset += len;
}

static int
regex_substitution(filter_ctxt *ctx, ap_regex_t *from, const char *to, char content)
{
    ap_regmatch_t pmatch[10];
    int nmatch;
    size_t len, offs;
    size_t s_from, s_to;
    size_t match;
    char *subs;
    int matches = 0;

    nmatch = sizeof(pmatch) / sizeof(ap_regmatch_t);
    offs = 0;
    while (!ap_regexec(from, ctx->buf + offs, nmatch, pmatch, 0))
    {
        ++matches;
        match = pmatch[0].rm_so;
        s_from = pmatch[0].rm_eo - match;
        subs = ap_pregsub(ctx->f->r->pool, to, ctx->buf + offs, nmatch, pmatch);
        s_to = strlen(subs);
        len = strlen(ctx->buf);
        offs += match;
        VERBOSEB(ctx->cfg->verbose,
            const char *f = apr_pstrndup(ctx->f->r->pool, ctx->buf + offs, s_from);
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                          "%s %c/RX: match at %s, substituting %s", ctx->f->r->uri, content,
                          f, subs);
        )
        if (s_to > s_from)
        {
            preserve(ctx, s_to - s_from);
            memmove(ctx->buf + offs + s_to, ctx->buf + offs + s_from,
                    len + 1 - s_from - offs);
            memcpy(ctx->buf + offs, subs, s_to);
        }
        else
        {
            memcpy(ctx->buf + offs, subs, s_to);
            memmove(ctx->buf + offs + s_to, ctx->buf + offs + s_from,
                    len + 1 - s_from - offs);
        }
        offs += s_to;
    }
    
    return matches;
}

static void
string_substitution(filter_ctxt *ctx, const char *from, const char *to, unsigned int flags)
{
    size_t len;
    size_t s_from, s_to;
    size_t match;
    char *found;

    s_from = strlen(from);
    s_to = strlen(to);
    for (found = strstr(ctx->buf, from); found;
         found = strstr(ctx->buf + match + s_to, from))
    {
        match = found - ctx->buf;
        if ((flags & M_ATSTART) && (match != 0))
            break;
        len = strlen(ctx->buf);
        if ((flags & M_ATEND) && (match < (len - s_from)))
            continue;
        VERBOSE(ctx->cfg->verbose,
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                "%s C: matched %s, substituting %s", ctx->f->r->uri,
                from, to));
        if (s_to > s_from)
        {
            preserve(ctx, s_to - s_from);
            memmove(ctx->buf + match + s_to, ctx->buf + match + s_from,
                    len + 1 - s_from - match);
            memcpy(ctx->buf + match, to, s_to);
        }
        else
        {
            memcpy(ctx->buf + match, to, s_to);
            memmove(ctx->buf + match + s_to, ctx->buf + match + s_from,
                    len + 1 - s_from - match);
        }
    }
}

static void
dump_content(filter_ctxt * ctx)
{
    urlmap *m;
    char c = 0;
    char content;
    
    if ((strcasecmp((char *) ctx->parser->name, "style") == 0 && !(ctx->cfg->extfix & EXTFIX_STYLES)) ||
        (strcasecmp((char *) ctx->parser->name, "script") == 0 && !(ctx->cfg->extfix & EXTFIX_SCRIPTS)))
    {
        AP_fwrite(ctx, ctx->buf, ctx->offset, 1);
        return;
    }
    
    if (strcasecmp((char *) ctx->parser->name, "style") == 0)
    {
        content = 'C';
    }
    else if (strcasecmp((char *) ctx->parser->name, "script") == 0)
    {
        content = 'E';
    }
    else
    {
        content = 'H';
    }
    
    pappend(ctx, &c, 1);        /* append null byte */

    /* parse the text for URLs */
    for (m = ctx->map; m; m = m->next)
    {
        if (!(m->flags & M_CDATA))
            continue;

        if (strcasecmp((char *) ctx->parser->name, "style") == 0)
        {
            if (regex_substitution(ctx, m->from.css_r, m->to_css, content) && (m->flags & M_LAST))
                break;
        }
        else if (strcasecmp((char *) ctx->parser->name, "script") == 0)
        {
            if (regex_substitution(ctx, m->from.js_r, m->to_js, content) && (m->flags & M_LAST))
                break;
        }
        else
        {
            if (m->flags & M_REGEX)
            {
                if (regex_substitution(ctx, m->from.r, m->to, content) && (m->flags & M_LAST))
                    break;
            }
            else
            {
                string_substitution(ctx, m->from.c, m->to, m->flags);
            }
        }
    }
    AP_fwrite(ctx, ctx->buf, strlen(ctx->buf), 1);
}

static void
pcdata(void *ctxt, const xmlChar * uchars, int length)
{
    const char *chars = (const char *) uchars;
    filter_ctxt *ctx = (filter_ctxt *) ctxt;

    if (ctx->cfg->extfix)
    {
        pappend(ctx, chars, length);
    }
    else
    {
        /* not sure if this should force-flush
         * (i.e. can one cdata section come in multiple calls?)
         */
        AP_fwrite(ctx, chars, length, 0);
    }
}

static char *
show_flags(apr_pool_t *pool, unsigned int flags)
{
    return apr_psprintf(pool, "%s%s%s%s%s%s%s%s%s%s%s",
                        (flags & M_HTML) ? "h" : "",
                        (flags & M_EVENTS) ? "e" : "",
                        (flags & M_CDATA) ? "c" : "",
                        (flags & M_STYLES) ? "s" : "",
                        (flags & M_REGEX) ? "R" : "",
                        (flags & M_ATSTART) ? "^" : "",
                        (flags & M_ATEND) ? "$" : "",
                        (flags & M_LAST) ? "L" : "",
                        (flags & M_NOTLAST) ? "l" : "",
                        (flags & M_INTERPOLATE_TO) ? "V" : "",
                        (flags & M_INTERPOLATE_FROM) ? "v" : "");
}

static void
pcomment(void *ctxt, const xmlChar * uchars)
{
    const char *chars = (const char *) uchars;
    filter_ctxt *ctx = (filter_ctxt *) ctxt;
    urlmap *m;
    
    DEBUG(ctx->cfg->verbose,
          ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
          "%s Got comment%s: %s", ctx->f->r->uri,
          ctx->cfg->strip_comments ? " (stripping)" : "",
          chars));

    if (ctx->cfg->strip_comments)
        return;
    
    pappend(ctx, "<!--", 4);
    pappend(ctx, chars, strlen(chars));
    pappend(ctx, "-->", 4);
    
    for (m = ctx->map; m; m = m->next)
    {
        if (!(m->flags & M_CDATA))
            continue;
        
        if (regex_substitution(ctx, m->from.js_r, m->to_js, 'H') && (m->flags & M_LAST))
            break;
    }

    AP_fwrite(ctx, ctx->buf, strlen(ctx->buf), 1);
    ctx->offset = 0;
}

static void
pendElement(void *ctxt, const xmlChar * uname)
{
    filter_ctxt *ctx = (filter_ctxt *) ctxt;
    const char *name = (const char *) uname;
    const htmlElemDesc *desc = htmlTagLookup(uname);

    if ((ctx->cfg->doctype == fpi_html) || (ctx->cfg->doctype == fpi_xhtml))
    {
        /* enforce html */
        if (!desc || desc->depr)
            return;

    }
    else if ((ctx->cfg->doctype == fpi_html) || (ctx->cfg->doctype == fpi_xhtml))
    {
        /* enforce html legacy */
        if (!desc)
            return;
    }
    /* TODO - implement HTML "allowed here" using the stack */
    /* nah.  Keeping the stack is too much overhead */

    if (ctx->offset > 0)
    {
        DEBUG(ctx->cfg->verbose,
              ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
              "%s End %s, dumping %ld bytes of content",
              ctx->f->r->uri, name, (long) ctx->offset));
        dump_content(ctx);
        ctx->offset = 0;        /* having dumped it, we can re-use the memory */
    }
    if (!desc || !desc->empty)
    {
        ap_fprintf(ctx->f->next, ctx->bb, "</%s>", name);
    }
}

static void
pstartElement(void *ctxt, const xmlChar * uname, const xmlChar ** uattrs)
{

    int required_attrs;
    int num_match;
    size_t offs, len;
    char *subs;
    rewrite_t is_uri;
    const char **a;
    urlmap *m;
    size_t s_to, s_from, match;
    filter_ctxt *ctx = (filter_ctxt *) ctxt;
    size_t nmatch;
    ap_regmatch_t pmatch[10];
    apr_array_header_t *linkattrs;
    int i;
    const char *name = (const char *) uname;
    const char **attrs = (const char **) uattrs;
    const htmlElemDesc *desc = htmlTagLookup(uname);

#ifdef HAVE_STACK
    const void **descp;
#endif
    int enforce = 0;

    if ((ctx->cfg->doctype == fpi_html) || (ctx->cfg->doctype == fpi_xhtml))
    {
        /* enforce html */
        enforce = 2;
        if (!desc || desc->depr)
            return;

    }
    else if ((ctx->cfg->doctype == fpi_html) || (ctx->cfg->doctype == fpi_xhtml))
    {
        enforce = 1;
        /* enforce html legacy */
        if (!desc)
        {
            return;
        }
    }
    if (!desc && enforce)
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->f->r, "Bogus HTML element %s dropped", name);
        return;
    }
    if (desc && desc->depr && (enforce == 2))
    {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->f->r,
                      "Deprecated HTML element %s dropped", name);
        return;
    }
#ifdef HAVE_STACK
    descp = apr_array_push(ctx->stack);
    *descp = desc;
    /* TODO - implement HTML "allowed here" */
#endif

    ap_fputc(ctx->f->next, ctx->bb, '<');
    ap_fputs(ctx->f->next, ctx->bb, name);

    required_attrs = 0;
    if ((enforce > 0) && (desc != NULL) && (desc->attrs_req != NULL))
        for (a = desc->attrs_req; *a; a++)
            ++required_attrs;

    if (attrs)
    {
        linkattrs = apr_hash_get(ctx->cfg->links, name, APR_HASH_KEY_STRING);
        for (a = attrs; *a; a += 2)
        {
            if (desc && enforce > 0)
            {
                switch (htmlAttrAllowed(desc, (xmlChar *) * a, 2 - enforce))
                {
                    case HTML_INVALID:
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->f->r,
                                      "Bogus HTML attribute %s of %s dropped", *a, name);
                        continue;
                    case HTML_DEPRECATED:
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->f->r,
                                      "Deprecated HTML attribute %s of %s dropped", *a, name);
                        continue;
                    case HTML_REQUIRED:
                        required_attrs--;       /* cross off the number still needed */
                        /* fallthrough - required implies valid */
                    default:
                        break;
                }
            }
            ctx->offset = 0;
            if (a[1])
            {
                pappend(ctx, a[1], strlen(a[1]) + 1);
                is_uri = ATTR_IGNORE;
                if (linkattrs)
                {
                    tattr *attrs = (tattr *) linkattrs->elts;

                    for (i = 0; i < linkattrs->nelts; ++i)
                    {
                        if (!strcmp(*a, attrs[i].val))
                        {
                            is_uri = ATTR_URI;
                            break;
                        }
                    }
                }
                if ((is_uri == ATTR_IGNORE) && (ctx->cfg->extfix & EXTFIX_SCRIPTS) && (ctx->cfg->events != NULL))
                {
                    for (i = 0; i < ctx->cfg->events->nelts; ++i)
                    {
                        tattr *attrs = (tattr *) ctx->cfg->events->elts;

                        if (!strcmp(*a, attrs[i].val))
                        {
                            is_uri = ATTR_EVENT;
                            break;
                        }
                    }
                }
                if ((is_uri == ATTR_IGNORE) && (ctx->cfg->extfix & EXTFIX_STYLES))
                {
                    if (strcmp(*a, "style") == 0)
                    {
                        is_uri = ATTR_STYLE;
                    }
                }
                switch (is_uri)
                {
                    case ATTR_URI:
                        num_match = 0;
                        for (m = ctx->map; m; m = m->next)
                        {
                            if (!(m->flags & M_HTML))
                                continue;
                            if (m->flags & M_REGEX)
                            {
                                nmatch = 10;
                                if (!ap_regexec(m->from.r, ctx->buf, nmatch, pmatch, 0))
                                {
                                    ++num_match;
                                    offs = match = pmatch[0].rm_so;
                                    s_from = pmatch[0].rm_eo - match;
                                    subs = ap_pregsub(ctx->f->r->pool, m->to, ctx->buf,
                                                      nmatch, pmatch);
                                    VERBOSEB(ctx->cfg->verbose,
                                        const char *f = apr_pstrndup(ctx->f->r->pool,
                                                                     ctx->buf + offs,
                                                                     s_from);
                                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                                                      "%s H/RX: match at %s, substituting %s",
                                                      ctx->f->r->uri, f, subs);
                                    )
                                    s_to = strlen(subs);
                                    len = strlen(ctx->buf);
                                    if (s_to > s_from)
                                    {
                                        preserve(ctx, s_to - s_from);
                                        memmove(ctx->buf + offs + s_to, ctx->buf + offs + s_from,
                                                len + 1 - s_from - offs);
                                        memcpy(ctx->buf + offs, subs, s_to);
                                    }
                                    else
                                    {
                                        memcpy(ctx->buf + offs, subs, s_to);
                                        memmove(ctx->buf + offs + s_to, ctx->buf + offs + s_from,
                                                len + 1 - s_from - offs);
                                    }
                                }
                            }
                            else
                            {
                                s_from = strlen(m->from.c);
                                if (!strncasecmp(ctx->buf, m->from.c, s_from))
                                {
                                    ++num_match;
                                    s_to = strlen(m->to);
                                    len = strlen(ctx->buf);
                                    VERBOSE(ctx->cfg->verbose,
                                            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                                            "%s H: matched %s, substituting %s",
                                            ctx->f->r->uri, m->from.c, m->to));
                                    if (s_to > s_from)
                                    {
                                        preserve(ctx, s_to - s_from);
                                        memmove(ctx->buf + s_to, ctx->buf + s_from,
                                                len + 1 - s_from);
                                        memcpy(ctx->buf, m->to, s_to);
                                    }
                                    else
                                    {   /* it fits in the existing space */
                                        memcpy(ctx->buf, m->to, s_to);
                                        memmove(ctx->buf + s_to, ctx->buf + s_from,
                                                len + 1 - s_from);
                                    }
                                    break;
                                }
                            }
                            /* URIs only want one match unless overridden in the config */
                            if ((num_match > 0) && !(m->flags & M_NOTLAST))
                                break;
                        }
                        break;

                    case ATTR_EVENT:
                        for (m = ctx->map; m; m = m->next)
                        {
                            if (!(m->flags & M_EVENTS))
                                continue;
                        
                            if (regex_substitution(ctx, m->from.js_r, m->to_js, 'E') && (m->flags & M_LAST))
                                break;
                        }
                        break;

                    case ATTR_STYLE:
                        for (m = ctx->map; m; m = m->next)
                        {
                            if (!(m->flags & M_STYLES))
                                continue;
                            
                            if (regex_substitution(ctx, m->from.css_r, m->to_css, 'C') && (m->flags & M_LAST))
                                break;
                        }
                        break;
                    
                    case ATTR_IGNORE:
                        break;
                }
            }
            if (!a[1])
                ap_fputstrs(ctx->f->next, ctx->bb, " ", a[0], NULL);
            else
            {
                if (ctx->cfg->flags != 0)
                    normalise(ctx->cfg->flags, ctx->buf);

                /* write the attribute, using pcharacters to html-escape
                   anything that needs it in the value.
                 */
                ap_fputstrs(ctx->f->next, ctx->bb, " ", a[0], "=\"", NULL);
                pcharacters(ctx, (const xmlChar *) ctx->buf, strlen(ctx->buf));
                ap_fputc(ctx->f->next, ctx->bb, '"');
            }
        }
    }
    ctx->offset = 0;
    if (desc && desc->empty)
        ap_fputs(ctx->f->next, ctx->bb, ctx->cfg->etag);
    else
        ap_fputc(ctx->f->next, ctx->bb, '>');

    if ((enforce > 0) && (required_attrs > 0))
    {
        /* if there are more required attributes than we found then complain */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->f->r,
                      "HTML element %s is missing %d required attributes", name, required_attrs);
    }
}

/* globals set once at startup */
static ap_regex_t *seek_meta_ctype;
static ap_regex_t *seek_charset;
static ap_regex_t *seek_meta;
static const apr_strmatch_pattern *seek_content;

static xmlCharEncoding
sniff_encoding(filter_ctxt * ctx, const char *cbuf, size_t bytes)
{
    request_rec *r = ctx->f->r;
    proxy_content_conf *cfg = ctx->cfg;
    xmlCharEncoding ret;
    char *p;
    ap_regmatch_t match[2];
    char *buf = (char *) cbuf;
    apr_xlate_t *convset;

    VERBOSE(ctx->cfg->verbose,
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "%s Content-Type is %s", r->uri, r->content_type));

    /* If we've got it in the HTTP headers, there's nothing to do */
    if (r->content_type && (p = ap_strcasestr(r->content_type, "charset="), p > 0))
    {
        p += 8;
        if (ctx->encoding = apr_pstrndup(r->pool, p, strcspn(p, " ;")), ctx->encoding)
        {
            VERBOSE(ctx->cfg->verbose,
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "%s Got charset %s from HTTP headers", ctx->f->r->uri,
                    ctx->encoding));
            if (ret =
                xmlParseCharEncoding(ctx->encoding), ((ret != XML_CHAR_ENCODING_ERROR) &&
                                                      (ret != XML_CHAR_ENCODING_NONE)))
            {
                return ret;
            }
        }
    }

    /* to sniff, first we look for BOM */
    if (ctx->encoding == NULL)
    {
        if (ret = xmlDetectCharEncoding((const xmlChar *) buf, bytes),
            ret != XML_CHAR_ENCODING_NONE)
        {
            VERBOSE(ctx->cfg->verbose,
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "%s Got charset from XML rules.", ctx->f->r->uri));
            return ret;
        }

        /* If none of the above, look for a META-thingey */
        if (ap_regexec(seek_meta_ctype, buf, 1, match, 0) == 0)
        {
            p = apr_pstrndup(r->pool, buf + match[0].rm_so, match[0].rm_eo - match[0].rm_so);
            if (ap_regexec(seek_charset, p, 2, match, 0) == 0)
                ctx->encoding = apr_pstrndup(r->pool, p + match[1].rm_so,
                                             match[1].rm_eo - match[1].rm_so);
        }
    }

    /* either it's set to something we found or it's still the default */
    if (ctx->encoding)
    {
        VERBOSE(ctx->cfg->verbose,
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "%s Got charset %s from HTML META", ctx->f->r->uri,
                ctx->encoding));
        if (ret = xmlParseCharEncoding(ctx->encoding),
            ((ret != XML_CHAR_ENCODING_ERROR) && (ret != XML_CHAR_ENCODING_NONE)))
        {
            return ret;
        }
        /* Unsupported charset.  Can we get (iconv) support through apr_xlate? */
        /* Aaargh!  libxml2 has undocumented <META-crap> support.  So this fails
         * if metafix is not active.  Have to make it conditional.
         */
        if (cfg->metafix)
        {
            VERBOSE(ctx->cfg->verbose,
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "Charset %s not supported by libxml2; trying apr_xlate",
                    ctx->encoding));
            if (apr_xlate_open(&convset, "UTF-8", ctx->encoding, r->pool) == APR_SUCCESS)
            {
                ctx->conv_in = apr_pcalloc(r->pool, sizeof(conv_t));
                ctx->conv_in->convset = convset;
                return XML_CHAR_ENCODING_UTF8;
            }
            else
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Charset %s not supported.  Consider aliasing it?", ctx->encoding);
            }
        }
        else
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Charset %s not supported.  Consider aliasing it or use metafix?",
                          ctx->encoding);
        }
    }


/* Use configuration default as a last resort */
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                  "%s No usable charset information; using configuration default", ctx->f->r->uri);
    return (cfg->default_encoding == XML_CHAR_ENCODING_NONE)
        ? XML_CHAR_ENCODING_8859_1 : cfg->default_encoding;
}

static meta *
metafix(request_rec * r, const char *buf /*, size_t bytes */, int verbose)
{
    meta *ret = NULL;
    size_t offs = 0;
    const char *p;
    const char *q;
    char *header;
    char *content;
    ap_regmatch_t pmatch[2];
    char delim;

    while (!ap_regexec(seek_meta, buf + offs, 2, pmatch, 0))
    {
        header = NULL;
        content = NULL;
        p = buf + offs + pmatch[1].rm_eo;
        while (!isalpha(*++p)) ;
        for (q = p; isalnum(*q) || (*q == '-'); ++q) ;
        header = apr_pstrndup(r->pool, p, q - p);
        if (strncasecmp(header, "Content-", 8))
        {
            /* find content=... string */
            p = apr_strmatch(seek_content, buf + offs + pmatch[0].rm_so,
                             pmatch[0].rm_eo - pmatch[0].rm_so);
            /* if it doesn't contain "content", ignore, don't crash! */
            if (p != NULL)
            {
                while (*p)
                {
                    p += 7;
                    while (*p && isspace(*p))
                        ++p;
                    if (*p != '=')
                        continue;
                    while (*p && isspace(*++p)) ;
                    if ((*p == '\'') || (*p == '"'))
                    {
                        delim = *p++;
                        for (q = p; *q != delim; ++q) ;
                    }
                    else
                    {
                        for (q = p; *q && !isspace(*q) && (*q != '>'); ++q) ;
                    }
                    content = apr_pstrndup(r->pool, p, q - p);
                    break;
                }
            }
        }
        else if (!strncasecmp(header, "Content-Type", 12))
        {
            ret = apr_palloc(r->pool, sizeof(meta));
            ret->start = pmatch[0].rm_so;
            ret->end = pmatch[0].rm_eo;
        }
        if (header && content)
        {
            VERBOSE(verbose,
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "Adding header [%s: %s] from HTML META", header, content));
            apr_table_setn(r->headers_out, header, content);
        }
        offs += pmatch[0].rm_eo;
    }
    return ret;
}

static const char *
interpolate_vars(request_rec * r, const char *str)
{
    const char *start;
    const char *end;
    const char *delim;
    const char *before;
    const char *after;
    const char *replacement;
    const char *var;

    for (;;)
    {
        start = str;
        if (start = ap_strstr_c(start, "${"), start == NULL)
            break;

        if (end = ap_strchr_c(start + 2, '}'), end == NULL)
            break;

        delim = ap_strchr_c(start, '|');
        before = apr_pstrndup(r->pool, str, start - str);
        after = end + 1;
        if (delim)
        {
            var = apr_pstrndup(r->pool, start + 2, delim - start - 2);
        }
        else
        {
            var = apr_pstrndup(r->pool, start + 2, end - start - 2);
        }
        replacement = apr_table_get(r->subprocess_env, var);
        if (!replacement)
        {
            if (delim)
            {
                replacement = apr_pstrndup(r->pool, delim + 1, end - delim - 1);
            }
            else
            {
                replacement = "";
            }
        }
        str = apr_pstrcat(r->pool, before, replacement, after, NULL);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Interpolating %s  =>  %s", var, replacement);
    }
    return str;
}

static void
fixup_rules(filter_ctxt * ctx)
{
    const char *thisval;
    urlmap *newp;
    urlmap *p;
    urlmap *prev = NULL;
    request_rec *r = ctx->f->r;
    int has_cond;

    for (p = ctx->cfg->map; p; p = p->next)
    {
        has_cond = -1;
        if (p->cond != NULL)
        {
            thisval = apr_table_get(r->subprocess_env, p->cond->env);
            if (!p->cond->val)
            {
                /* required to be "anything" */
                if (thisval)
                    has_cond = 1;       /* satisfied */
                else
                    has_cond = 0;       /* unsatisfied */
            }
            else
            {
                if (thisval && !strcasecmp(p->cond->val, thisval))
                {
                    has_cond = 1;       /* satisfied */
                }
                else
                {
                    has_cond = 0;       /* unsatisfied */
                }
            }
            if (((has_cond == 0) && (p->cond->rel == 1))
                || ((has_cond == 1) && (p->cond->rel == -1)))
            {
                continue;       /* condition is unsatisfied */
            }
        }

        newp = apr_pmemdup(r->pool, p, sizeof(urlmap));

        if (newp->flags & M_INTERPOLATE_FROM)
        {
            newp->from.c = interpolate_vars(r, newp->from.c);
            if (!newp->from.c || !*newp->from.c)
                continue;       /* don't use empty from-pattern */
            if (newp->flags & M_REGEX)
            {
                newp->from.r = ap_pregcomp(r->pool, newp->from.c, newp->regflags);
            }
        }
        if (newp->flags & M_INTERPOLATE_TO)
        {
            newp->to = interpolate_vars(r, newp->to);
        }
        /* evaluate p->cond; continue if unsatisfied */
        /* create new urlmap with memcpy and append to map */
        /* interpolate from if flagged to do so */
        /* interpolate to if flagged to do so */

        if (prev != NULL)
            prev->next = newp;
        else
            ctx->map = newp;
        prev = newp;
    }

    if (prev)
        prev->next = NULL;
}

static int
javascript_content(const char *content_type)
{
    return strncasecmp(content_type, "application/x-javascript", 24) == 0 ||
        strncasecmp(content_type, "application/javascript", 22) == 0 ||
        strncasecmp(content_type, "application/ecmascript", 22) == 0 ||
        strncasecmp(content_type, "text/javascript", 15) == 0 ||
        strncasecmp(content_type, "text/ecmascript", 15) == 0;
}

static filter_ctxt *
check_filter_init(ap_filter_t * f)
{
    filter_ctxt *fctx;

    if (!f->ctx)
    {
        proxy_content_conf *cfg = ap_get_module_config(f->r->per_dir_config, &proxy_content_module);
        const char *force = apr_table_get(f->r->subprocess_env, "PROXY_HTML_FORCE");

        if (!force)
        {
            if (!f->r->proxyreq)
            {
                VERBOSE(cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      "%s Non-proxy request; not inserting proxy-content filter",
                                      f->r->uri));
                ap_remove_output_filter(f);
                return NULL;
            }
            else if (!f->r->content_type)
            {
                VERBOSE(cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      "%s No content-type; bailing out of proxy-content filter",
                                      f->r->uri));
                ap_remove_output_filter(f);
                return NULL;
            }
            else if (strncasecmp(f->r->content_type, "text/html", 9) &&
                     strncasecmp(f->r->content_type, "application/xhtml+xml", 21) &&
                     strncasecmp(f->r->content_type, "text/css", 8) &&
                     !javascript_content(f->r->content_type))
            {
                VERBOSE(cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      "%s Non-HTML/CSS/JS content %s; not inserting proxy-content filter",
                                      f->r->uri, f->r->content_type));
                ap_remove_output_filter(f);
                return NULL;
            }
            else if (!(cfg->extfix & EXTFIX_STYLES) && strncasecmp(f->r->content_type, "text/css", 8) == 0)
            {
                VERBOSE(cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      "%s Extended mode disabled for CSS; not inserting proxy-content filter",
                                      f->r->uri));
                ap_remove_output_filter(f);
                return NULL;
            }
            else if (!(cfg->extfix & EXTFIX_SCRIPTS) && javascript_content(f->r->content_type))
            {
                VERBOSE(cfg->verbose,
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      "%s Extended mode disabled for Javascript; not inserting proxy-content filter",
                                      f->r->uri));
                ap_remove_output_filter(f);
                return NULL;
            }
        }
        if (!cfg->links)
        {
            VERBOSE(cfg->verbose,
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                  "%s No links configured: nothing for proxy-content filter to do",
                                  f->r->uri));
            ap_remove_output_filter(f);
            return NULL;
        }

        fctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(filter_ctxt));
        fctx->f = f;
        fctx->bb = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
        fctx->saved_buckets = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
        fctx->cfg = cfg;
        apr_table_unset(f->r->headers_out, "Content-Length");

        if (cfg->interp)
            fixup_rules(fctx);
        else
            fctx->map = cfg->map;
        
        if (strcasecmp(f->r->content_type, "text/html") == 0 ||
            strcasecmp(f->r->content_type, "application/xhtml+xml") == 0)
        {
            fctx->content_type = CONTENT_TYPE_HTML;
        }
        else if (strcasecmp(f->r->content_type, "text/css") == 0)
        {
            DEBUG(cfg->verbose,
                  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                "%s content type is CSS", f->r->uri));
            fctx->content_type = CONTENT_TYPE_CSS;
        }
        else if (javascript_content(f->r->content_type))
        {
            DEBUG(cfg->verbose,
                  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                "%s content type is Javascript", f->r->uri));
            fctx->content_type = CONTENT_TYPE_JS;
        }
        
        /* defer dealing with charset_out until after sniffing charset_in
         * so we can support setting one to t'other.
         */
    }
    
    return f->ctx;
}

static int
proxy_content_filter_html(ap_filter_t * f, apr_bucket_brigade * bb)
{
    filter_ctxt *ctx = (filter_ctxt *) f->ctx;
    apr_xlate_t *convset;
    const char *charset = NULL;
    apr_bucket *b;
    meta *m = NULL;
    xmlCharEncoding enc;
    const char *buf = 0;
    apr_size_t bytes = 0;

#ifndef USE_OLD_LIBXML2
    int xmlopts = XML_PARSE_RECOVER | XML_PARSE_NONET |
        XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#endif

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_METADATA(b))
        {
            if (APR_BUCKET_IS_EOS(b))
            {
                if (ctx->parser != NULL)
                {
                    consume_buffer(ctx, buf, 0, 1);
                }
                APR_BRIGADE_INSERT_TAIL(ctx->bb, apr_bucket_eos_create(ctx->bb->bucket_alloc));
                return ap_pass_brigade(ctx->f->next, ctx->bb);
            }
            else if (APR_BUCKET_IS_FLUSH(b))
            {
                /* pass on flush, except at start where it would cause
                 * headers to be sent before doc sniffing
                 */
                if (ctx->parser != NULL)
                {
                    ap_fflush(ctx->f->next, ctx->bb);
                }
            }
        }
        else if (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS)
        {
            if (ctx->parser == NULL)
            {
                if (buf[bytes] != 0)
                {
                    /* make a string for parse routines to play with */
                    char *buf1 = apr_palloc(f->r->pool, bytes + 1);

                    memcpy(buf1, buf, bytes);
                    buf1[bytes] = 0;
                    buf = buf1;
                }
                /* For publishing systems that insert crap at the head of a
                 * page that buggers up the parser.  Search to first instance
                 * of some relatively sane, or at least parseable, element.
                 */
                if (ctx->cfg->skipto != NULL)
                {
                    char *p = ap_strchr_c(buf, '<');
                    tattr *starts = (tattr *) ctx->cfg->skipto->elts;
                    int found = 0;

                    while (!found && *p)
                    {
                        int i;

                        for (i = 0; i < ctx->cfg->skipto->nelts; ++i)
                        {
                            if (!strncasecmp(p + 1, starts[i].val, strlen(starts[i].val)))
                            {
                                bytes -= (p - buf);
                                buf = p;
                                found = 1;
                                VERBOSE(ctx->cfg->verbose,
                                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                                        "Skipped to first <%s> element",
                                        starts[i].val));
                                break;
                            }
                        }
                        p = ap_strchr_c(p + 1, '<');
                    }
                    if (p == NULL)
                    {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r,
                                      "Failed to find start of recognised HTML!");
                    }
                }

                enc = sniff_encoding(ctx, buf, bytes);
                /* now we have input charset, set output charset too */
                if (ctx->cfg->charset_out)
                {
                    if (!strcmp(ctx->cfg->charset_out, "*"))
                        charset = ctx->encoding;
                    else
                        charset = ctx->cfg->charset_out;
                    if (strcasecmp(charset, "utf-8"))
                    {
                        if (apr_xlate_open(&convset, charset, "UTF-8", f->r->pool) == APR_SUCCESS)
                        {
                            ctx->conv_out = apr_pcalloc(f->r->pool, sizeof(conv_t));
                            ctx->conv_out->convset = convset;
                        }
                        else
                        {
                            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r,
                                          "Output charset %s not supported.  Falling back to UTF-8",
                                          charset);
                        }
                    }
                }
                if (ctx->conv_out)
                {
                    const char *ctype = apr_psprintf(f->r->pool,
                                                     "text/html;charset=%s", charset);

                    ap_set_content_type(f->r, ctype);
                }
                else
                {
                    ap_set_content_type(f->r, "text/html;charset=utf-8");
                }
                ap_fputs(f->next, ctx->bb, ctx->cfg->doctype);
                ctx->parser = htmlCreatePushParserCtxt(&sax, ctx, buf, 4, 0, enc);
                buf += 4;
                bytes -= 4;
                if (ctx->parser == NULL)
                {
                    apr_status_t rv = ap_pass_brigade(f->next, bb);

                    ap_remove_output_filter(f);
                    return rv;
                }
                apr_pool_cleanup_register(f->r->pool, ctx->parser,
                                          (int(*)(void*))htmlFreeParserCtxt, apr_pool_cleanup_null);
#ifndef USE_OLD_LIBXML2
                if (xmlopts = xmlCtxtUseOptions(ctx->parser, xmlopts), xmlopts)
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r,
                                  "Unsupported parser opts %x", xmlopts);
#endif
                if (ctx->cfg->metafix)
                    m = metafix(f->r, buf, ctx->cfg->verbose);

                if (m)
                {
                    consume_buffer(ctx, buf, m->start, 0);
                    consume_buffer(ctx, buf + m->end, bytes - m->end, 0);
                }
                else
                {
                    consume_buffer(ctx, buf, bytes, 0);
                }
            }
            else
            {
                consume_buffer(ctx, buf, bytes, 0);
            }
        }
        else
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "Error in bucket read");
        }
    }
    
    return APR_SUCCESS;
}

static void
remember_matched_bucket(filter_ctxt *ctx, apr_bucket *b)
{
    unsigned int last = 0;
    
    while (last < ctx->matched_size && ctx->matched_bucket[last] != NULL)
    {
        ++last;
    }
    
    if (last == ctx->matched_size)
    {
        unsigned int i;

        ctx->matched_size *= 4;
        if (ctx->matched_size == 0)
        {
            ctx->matched_size = 32;
        }
        
        ctx->matched_bucket = realloc(ctx->matched_bucket, ctx->matched_size * sizeof(void *));
        
        /* realloc() doesn't zero the new memory. */
        for (i = last + 1; i < ctx->matched_size; ++i)
        {
            ctx->matched_bucket[i] = NULL;
        }
    }
    
    ctx->matched_bucket[last] = b;
}

static int
bucket_is_previous_match(filter_ctxt *ctx, apr_bucket *b)
{
    unsigned int i;
    
    for (i = 0; i < ctx->matched_size && ctx->matched_bucket[i] != NULL; i++)
    {
        if (ctx->matched_bucket[i] == b)
        {
            return 1;
        }
    }
    
    return 0;
}

static apr_bucket *
combine_buckets(filter_ctxt *ctx, apr_bucket *a, apr_bucket *b, apr_pool_t *pool)
{
    const char *a_data, *b_data;
    char *buffer;
    size_t a_bytes, b_bytes;
    
    DEBUG(ctx->cfg->verbose,
          ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                        "combining buckets 0x%lx (%lu bytes) + 0x%lx (%lu bytes)",
                        (unsigned long) a, (unsigned long) a->length,
                        (unsigned long) b, (unsigned long) b->length));

    if (apr_bucket_read(a, &a_data, &a_bytes, APR_BLOCK_READ) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->f->r,
                      "%s(): error reading from 'a' bucket", __func__);
    }
    if (apr_bucket_read(b, &b_data, &b_bytes, APR_BLOCK_READ) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->f->r,
                      "%s(): error reading from 'b' bucket", __func__);
    }
    
    buffer = apr_palloc(pool, a_bytes + b_bytes);
    memcpy(buffer, a_data, a_bytes);
    memcpy(buffer + a_bytes, b_data, b_bytes);
    return apr_bucket_pool_create(buffer, a_bytes + b_bytes, pool,
                                  ctx->f->r->connection->bucket_alloc);
}

static void
insert_saved_buckets_before(filter_ctxt *ctx, apr_bucket *b, const char *reason)
{
    int n = 0;
    apr_bucket *saved = APR_BRIGADE_FIRST(ctx->saved_buckets);
    while (saved != APR_BRIGADE_SENTINEL(ctx->saved_buckets))
    {
        ++n;
        apr_bucket *next = APR_BUCKET_NEXT(saved);
        APR_BUCKET_REMOVE(saved);
        APR_BUCKET_INSERT_BEFORE(b, saved);

        DEBUG(ctx->cfg->verbose,
              ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                            "%s, reinserted saved bucket 0x%lx to output stream",
                            reason, (unsigned long) saved));
        
        saved = next;
    }
    
    if (n > 1)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ctx->f->r,
                      "%d buckets moved from saved brigade, expected only 1", n);
    }
}

static int
apply_regex_to_bucket(filter_ctxt *ctx, apr_pool_t *temp_pool, apr_bucket **b,
                      ap_regex_t *re, const char *to)
{
    ap_filter_t *f = ctx->f;
    const char *data;
    size_t bytes;

    if (APR_BUCKET_IS_METADATA(*b))
    {
        /* If a bucket is stashed in the saved brigade to match URLs
         * that span buckets, it can be pulled off and sent along since
         * this is either end-of-stream or a flush is expected.
         */
        
        insert_saved_buckets_before(ctx, *b, "got metadata");
    }
    else
    {
        if (bucket_is_previous_match(ctx, *b))
        {
            /* If this bucket is a result of a previous match, don't try to
             * match against it again as that will almost certainly result
             * in a mangled URL.  Check for a bucket saved in the context
             * for a potential spanning match and send both of them along
             * in the brigade.
             */
            
            insert_saved_buckets_before(ctx, *b, "got previous match");
        }
        else
        {
            if (!APR_BRIGADE_EMPTY(ctx->saved_buckets))
            {
                apr_bucket *combined, *saved;
                
                /* Create a new bucket that contains both the saved bytes
                 * from the previous bucket and the current bucket so that
                 * a regex match will catch URLs that spanned the two
                 * buckets.  Then insert the new bucket in place of the
                 * current bucket and clean up the old ones.
                 */
                
                saved = APR_BRIGADE_FIRST(ctx->saved_buckets);
                combined = combine_buckets(ctx, saved, *b, f->r->pool);
                apr_bucket_delete(saved);
                APR_BUCKET_INSERT_BEFORE(*b, combined);
                apr_bucket_delete(*b);
                *b = combined;
            }
            
            if (apr_bucket_read(*b, &data, &bytes, APR_BLOCK_READ) == APR_SUCCESS)
            {
                apr_status_t rv;
                size_t offset = 0;
                char *buffer;
                ap_regmatch_t pmatch[10];
                int nmatch;
        
                nmatch = sizeof(pmatch) / sizeof(ap_regmatch_t);

                buffer = apr_pstrmemdup(temp_pool, data, bytes);
        
                DEBUG(ctx->cfg->verbose,
                      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                    "%s read %ld bytes from bucket 0x%lx: %s", f->r->uri,
                                    (long) bytes, (unsigned long) *b,
                                    apr_pstrndup(f->r->pool, buffer, bytes > 100 ? 100 : bytes)));

                while (offset < bytes && !ap_regexec(re, buffer + offset, nmatch, pmatch, 0))
                {
                    size_t length = pmatch[0].rm_eo - pmatch[0].rm_so;
                    char *subs = ap_pregsub(f->r->pool, to, buffer + offset, nmatch, pmatch);
                    apr_bucket *old, *substitution;

                    VERBOSEB(ctx->cfg->verbose,
                        const char *s = apr_pstrndup(temp_pool, buffer + offset + pmatch[0].rm_so,
                                                     length);
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                      "%s C/RX: match at %s (offset %ld + %d), substituting %s",
                                      f->r->uri, s, (long) offset, pmatch[0].rm_so, subs);
                    )

                    if ((rv = apr_bucket_split(*b, pmatch[0].rm_so)) != APR_SUCCESS)
                    {
                        VERBOSE(ctx->cfg->verbose,
                                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                              "%s before split failure at offset %ld, rv=%d",
                                              f->r->uri, (long) offset + pmatch[0].rm_so, rv));
                        return 0;
                    }
                    *b = APR_BUCKET_NEXT(*b);
                    substitution = apr_bucket_transient_create(subs, strlen(subs),
                                                               f->r->connection->bucket_alloc);
                    remember_matched_bucket(ctx, substitution);
                    APR_BUCKET_INSERT_BEFORE(*b, substitution);
                    if ((rv = apr_bucket_split(*b, length)) != APR_SUCCESS)
                    {
                        VERBOSE(ctx->cfg->verbose,
                                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                              "%s after split failure at offset %ld, rv=%d",
                                              f->r->uri, (long) length, rv));
                        return 0;
                    }
                    old = *b;
                    *b = APR_BUCKET_NEXT(*b);
                    apr_bucket_delete(old);

                    offset += pmatch[0].rm_so + length;
                }
            }
        }
    }
    
    return 1;
}

/* The largest prefix added by comp_urlmap_css_js() is for CSS: url(
 * with an optional single or double quote.
 */
#define LARGEST_URL_PREFIX_LENGTH 5

static void
save_bucket_for_span_check(filter_ctxt *ctx, apr_bucket **b)
{
    if (!bucket_is_previous_match(ctx, *b))
    {
        /* So long as the bucket isn't the result of a previous match
         * substitution, split it to save off enough bytes from the end
         * to form a complete match, remove that new bucket from the
         * brigade and stash it somewhere safe for the next bucket that
         * comes along.
         *
         * If the bucket isn't big enough to split, save the whole thing.
         */
        
        long offset = (long)((*b)->length) - (ctx->cfg->max_url_length + LARGEST_URL_PREFIX_LENGTH);
        
        if (offset > 0)
        {
            apr_bucket *save;
            
            /* The bucket is bigger than the largest matchable URL, so
             * it is safe to split off just the bytes from the end.
             */
            
            DEBUG(ctx->cfg->verbose,
                  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                                "split %lu byte bucket 0x%lx at offset %ld",
                                (unsigned long) (*b)->length, (unsigned long) *b, (long) offset));

            apr_bucket_split(*b, offset);
            save = APR_BUCKET_NEXT(*b);
            APR_BUCKET_REMOVE(save);
            APR_BRIGADE_INSERT_TAIL(ctx->saved_buckets, save);
            apr_bucket_setaside(save, ctx->f->r->pool);

            DEBUG(ctx->cfg->verbose,
                  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                                "saved bucket is 0x%lx, %lu bytes",
                                (unsigned long) save, (unsigned long) save->length));
        }
        else
        {
            apr_bucket *prev;
            
            DEBUG(ctx->cfg->verbose,
                  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                                "saving entire %lu byte bucket 0x%lx",
                                (unsigned long) (*b)->length, (unsigned long) *b));
            
            prev = APR_BUCKET_PREV(*b);
            APR_BUCKET_REMOVE(*b);
            APR_BRIGADE_INSERT_TAIL(ctx->saved_buckets, *b);
            apr_bucket_setaside(*b, ctx->f->r->pool);
            *b = prev;
        }
    }
}

static int
proxy_content_filter_cssjs(ap_filter_t *f, apr_bucket_brigade *bb)
{
    filter_ctxt *ctx = (filter_ctxt *) f->ctx;
    urlmap *m;
    apr_bucket *b;
    apr_pool_t *pool;
    int stop_processing;

    if (apr_pool_create(&pool, f->r->pool) != APR_SUCCESS)
    {
        pool = f->r->pool;
    }
    
    /* Any save buckets are left over from a previous brigade and should
     * be put at the head of this brigade to maintain their order in the
     * response stream.
     */
    insert_saved_buckets_before(ctx, APR_BRIGADE_FIRST(bb), "new brigade");

    stop_processing = 0;
    for (m = ctx->map; m && !stop_processing; m = m->next)
    {
        ap_regex_t *re;
        const char *to;

        if (!(m->flags & M_CDATA))
        {
            continue;
        }
        
        switch (ctx->content_type)
        {
            case CONTENT_TYPE_CSS:
                re = m->from.css_r;
                to = m->to_css;
                break;
                
            case CONTENT_TYPE_JS:
                re = m->from.js_r;
                to = m->to_js;
                break;
            
            default:
                /* Should never get here, but makes the compiler happy. */
                break;
        }
        
        /* Any saved buckets here are from the end of this brigade, saved
         * by the prior regex.  They should be put back at the tail of the
         * brigade for examination with the next regex.
         */
        insert_saved_buckets_before(ctx, APR_BRIGADE_SENTINEL(bb), "restarting brigade walk with new regex");

        DEBUG(ctx->cfg->verbose,
              ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                            "%s testing %s", f->r->uri, m->from.c));
        
        b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb))
        {
            DEBUG(ctx->cfg->verbose,
                  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                "bucket 0x%x, type=%s, length=%u", (uintptr_t) b, b->type->name, b->length));

            if (!apply_regex_to_bucket(ctx, pool, &b, re, to))
            {
                DEBUG(ctx->cfg->verbose,
                      ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                                    "%s regex apply failure, stopping early", f->r->uri));
                stop_processing = 1;
                break;
            }
            
            /* It's possible that a URL will span two or more buckets.  When
             * this happens, I might need to split the bucket and hold on to
             * enough bytes from the end so that they can be prepended to
             * the next bucket and successfully match the URL.
             *
             * This bucket might also be the last one in a brigade, so it
             * is placed in a temporary brigade in the context struct to
             * cover this case.
             *
             * A final wrinkle is that the bucket might be the result of
             * a previous match.  In a perfect world, I'd like to mark a
             * bucket with a flag, but this isn't possible short of
             * creating a new bucket type, which I don't want to do right
             * now.  Instead, I keep track of the addresses of buckets
             * that contain a substituted string in a simple array.
             */
            
            if (!APR_BUCKET_IS_METADATA(b))
            {
                save_bucket_for_span_check(ctx, &b);
            }
            
            b = APR_BUCKET_NEXT(b);
        }
    }
    
    if (pool != f->r->pool)
    {
        apr_pool_clear(pool);
    }
    
    if (ctx->matched_bucket)
    {
        free(ctx->matched_bucket);
        ctx->matched_bucket = NULL;
        ctx->matched_size = 0;
    }
    
    DEBUG(ctx->cfg->verbose,
          ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, ctx->f->r,
                        "passing brigade"));

    return ap_pass_brigade(f->next, bb);
}

static int
proxy_content_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_status_t result = APR_SUCCESS;
    filter_ctxt *ctxt = check_filter_init(f);

    if (!ctxt)
        return ap_pass_brigade(f->next, bb);
    
    switch (ctxt->content_type)
    {
        case CONTENT_TYPE_HTML:
            result = proxy_content_filter_html(f, bb);
            break;
        
        case CONTENT_TYPE_CSS:
        case CONTENT_TYPE_JS:
            result = proxy_content_filter_cssjs(f, bb);
            break;
            
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, "Unhandled content type in %s", __func__);
            result = APR_EGENERAL;
    }
    
    /*ap_fflush(ctxt->f->next, ctxt->bb) ;        // uncomment for debug */
    apr_brigade_cleanup(bb);
    return result;
}

static void *
proxy_content_config(apr_pool_t * pool, char *x)
{
    proxy_content_conf *ret = apr_pcalloc(pool, sizeof(proxy_content_conf));

    ret->doctype = DEFAULT_DOCTYPE;
    ret->etag = DEFAULT_ETAG;
    ret->bufsz = 8192;
    ret->default_encoding = XML_CHAR_ENCODING_NONE;
    /* ret->interp = 1; */
    /* don't initialise links and events until they get set/used */
    return ret;
}

static void *
proxy_content_merge(apr_pool_t * pool, void *BASE, void *ADD)
{
    urlmap *m;
    
    proxy_content_conf *base = (proxy_content_conf *) BASE;
    proxy_content_conf *add = (proxy_content_conf *) ADD;
    proxy_content_conf *conf = apr_palloc(pool, sizeof(proxy_content_conf));

    /* don't merge declarations - just use the most specific */
    conf->links = (add->links == NULL) ? base->links : add->links;
    conf->events = (add->events == NULL) ? base->events : add->events;

    conf->default_encoding = (add->default_encoding == XML_CHAR_ENCODING_NONE)
        ? base->default_encoding : add->default_encoding;
    conf->charset_out = (add->charset_out == NULL) ? base->charset_out : add->charset_out;

    if (add->map && base->map)
    {
        urlmap *a, *tail;

        /* Merge URL mappings so that the higher scope (global, vhost) comes
         * before lower scope (location directives), and maintains the order
         * the mappings are defined in the configuration within each section.
         * mod_proxy_html takes a shortcut and adds mappings to the head of
         * list, effectively reversing the order of the mappings.
         *
         * This is important because often mappings are redundant:
         * http://server/path and /path, and you want the first (longer)
         * mapping to be used first when substituting inside HTML comments.
         * It isn't a problem for CSS or Javascript substitutions, because
         * we can rely on a recognizable token to immediately precede the
         * mapping and that will avoid matching /path against
         * http://server/path.
         */

        tail = conf->map = NULL;
        for (a = base->map; a; a = a->next)
        {
            urlmap *dupmap = apr_pmemdup(pool, a, sizeof(urlmap));
            dupmap->next = NULL;
            
            if (tail)
            {
                tail->next = dupmap;
                tail = dupmap;
            }
            else
            {
                conf->map = tail = dupmap;
            }
        }
        for (a = add->map; a; a = a->next)
        {
            urlmap *dupmap = apr_pmemdup(pool, a, sizeof(urlmap));
            dupmap->next = NULL;
            
            if (tail)
            {
                tail->next = dupmap;
                tail = dupmap;
            }
            else
            {
                conf->map = tail = dupmap;
            }
        }
    }
    else
        conf->map = add->map ? add->map : base->map;
    
    for (m = conf->map; m != NULL; m = m->next)
    {
        if ((m->flags & M_REGEX) == 0)
        {
            unsigned int length = strlen(m->from.c);
            if (length > conf->max_url_length)
            {
                conf->max_url_length = length;
            }
        }
    }
    
    conf->doctype = (add->doctype == DEFAULT_DOCTYPE) ? base->doctype : add->doctype;
    conf->etag = (add->etag == DEFAULT_ETAG) ? base->etag : add->etag;
    conf->bufsz = add->bufsz;
    if (add->flags & NORM_RESET)
    {
        conf->flags = add->flags ^ NORM_RESET;
        conf->metafix = add->metafix;
        conf->extfix = add->extfix;
        conf->interp = add->interp;
        conf->strip_comments = add->strip_comments;
        conf->skipto = add->skipto;
        conf->verbose = add->verbose;
    }
    else
    {
        conf->flags = base->flags | add->flags;
        conf->metafix = base->metafix | add->metafix;
        conf->extfix = base->extfix | add->extfix;
        conf->interp = base->interp | add->interp;
        conf->strip_comments = base->strip_comments | add->strip_comments;
        conf->skipto = add->skipto ? add->skipto : base->skipto;
        conf->verbose = base->verbose | add->verbose;
    }

    return conf;
}

#define REGFLAG(n,s,c) ( (s&&(ap_strchr_c((s),(c))!=NULL)) ? (n) : 0 )
#define XREGFLAG(n,s,c) ( (!s||(ap_strchr_c((s),(c))==NULL)) ? (n) : 0 )

static void
comp_urlmap_css_js(apr_pool_t *pool, urlmap *newmap, const char *flags, int verbose)
{
    char *expression;
    unsigned int regflags;

    regflags
        = REGFLAG(AP_REG_EXTENDED, flags, 'x')
        | REGFLAG(AP_REG_ICASE, flags, 'i')
        | REGFLAG(AP_REG_NOSUB, flags, 'n')
        | REGFLAG(AP_REG_NEWLINE, flags, 's');
    
    expression = apr_psprintf(pool, "url\\(\\s*(['\"]?)%s([^\\)]*)(['\"]?)\\s*\\)", newmap->from.c);
    newmap->from.css_r = ap_pregcomp(pool, expression, regflags);
    newmap->to_css = apr_psprintf(pool, "url($1%s$2$3)", newmap->to);
    DEBUG(verbose,
          ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, pool,
                        "URL mapping (CSS) %s -> %s, flags=%s",
                        expression, newmap->to_css, flags));
    
    expression = apr_psprintf(pool, "([ \\t\\n+:=\\(,\\[])(['\"])%s", newmap->from.c);
    newmap->from.js_r = ap_pregcomp(pool, expression, regflags);
    newmap->to_js = apr_psprintf(pool, "$1$2%s", newmap->to);
    DEBUG(verbose,
          ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, pool,
                        "URL mapping (JS) %s -> %s, flags=%s",
                        expression, newmap->to_js, flags));
}

static void
comp_urlmap(apr_pool_t * pool, urlmap * newmap,
            const char *from, const char *to, const char *flags, const char *cond,
            int verbose)
{
    char *eq;
    
    DEBUG(verbose,
          ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, pool,
                        "URL mapping %s -> %s, flags=%s, cond=%s",
                        from, to, flags, cond ? cond : ""));

    newmap->flags
        = XREGFLAG(M_HTML, flags, 'h')
        | XREGFLAG(M_EVENTS, flags, 'e')
        | XREGFLAG(M_CDATA, flags, 'c')
        | XREGFLAG(M_STYLES, flags, 's')
        | REGFLAG(M_ATSTART, flags, '^')
        | REGFLAG(M_ATEND, flags, '$')
        | REGFLAG(M_REGEX, flags, 'R')
        | REGFLAG(M_LAST, flags, 'L')
        | REGFLAG(M_NOTLAST, flags, 'l')
        | REGFLAG(M_INTERPOLATE_TO, flags, 'V')
        | REGFLAG(M_INTERPOLATE_FROM, flags, 'v');
    if ((newmap->flags & M_INTERPOLATE_FROM) || !(newmap->flags & M_REGEX))
    {
        newmap->from.c = from;
        newmap->to = to;
        comp_urlmap_css_js(pool, newmap, flags, verbose);
    }
    else
    {
        newmap->regflags
            = REGFLAG(AP_REG_EXTENDED, flags, 'x')
            | REGFLAG(AP_REG_ICASE, flags, 'i')
            | REGFLAG(AP_REG_NOSUB, flags, 'n') | REGFLAG(AP_REG_NEWLINE, flags, 's');
        newmap->from.r = ap_pregcomp(pool, from, newmap->regflags);
        newmap->to = to;
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, pool,
                      "ProxyHTMLURLMap regex %s not supported for CSS/JS content", from);
    }
    if (cond != NULL)
    {
        char* cond_copy;
        newmap->cond = apr_pcalloc(pool, sizeof(rewritecond));
        if (cond[0] == '!')
        {
            newmap->cond->rel = -1;
            newmap->cond->env = cond_copy = apr_pstrdup(pool, cond + 1);
        }
        else
        {
            newmap->cond->rel = 1;
            newmap->cond->env = cond_copy = apr_pstrdup(pool, cond);
        }
        eq = ap_strchr(++cond_copy, '=');
        if (eq)
        {
            *eq = 0;
            newmap->cond->val = eq + 1;
        }
    }
    else
    {
        newmap->cond = NULL;
    }
}

static const char *
set_urlmap(cmd_parms * cmd, void *CFG, const char *args)
{
    proxy_content_conf *cfg = (proxy_content_conf *) CFG;
    urlmap *map;
    apr_pool_t *pool = cmd->pool;
    urlmap *newmap;
    const char *usage = "Usage: ProxyHTMLURLMap from-pattern to-pattern [flags] [cond]";
    const char *from;
    const char *to;
    const char *flags;
    const char *cond = NULL;

    if (from = ap_getword_conf(cmd->pool, &args), !from)
        return usage;
    if (to = ap_getword_conf(cmd->pool, &args), !to)
        return usage;
    flags = ap_getword_conf(cmd->pool, &args);
    if (flags && *flags)
        cond = ap_getword_conf(cmd->pool, &args);
    if (cond && !*cond)
        cond = NULL;

    /* the args look OK, so let's use them */
    newmap = apr_palloc(pool, sizeof(urlmap));
    newmap->next = NULL;
    if (cfg->map)
    {
        for (map = cfg->map; map->next; map = map->next) ;
        map->next = newmap;
    }
    else
        cfg->map = newmap;

    comp_urlmap(cmd->pool, newmap, from, to, flags, cond, cfg->verbose);
    return NULL;
}

static const char *
set_doctype(cmd_parms * cmd, void *CFG, const char *t, const char *l)
{
    proxy_content_conf *cfg = (proxy_content_conf *) CFG;

    if (!strcasecmp(t, "xhtml"))
    {
        cfg->etag = xhtml_etag;
        if (l && !strcasecmp(l, "legacy"))
            cfg->doctype = fpi_xhtml_legacy;
        else
            cfg->doctype = fpi_xhtml;
    }
    else if (!strcasecmp(t, "html"))
    {
        cfg->etag = html_etag;
        if (l && !strcasecmp(l, "legacy"))
            cfg->doctype = fpi_html_legacy;
        else
            cfg->doctype = fpi_html;
    }
    else
    {
        cfg->doctype = apr_pstrdup(cmd->pool, t);
        if (l && ((l[0] == 'x') || (l[0] == 'X')))
            cfg->etag = xhtml_etag;
        else
            cfg->etag = html_etag;
    }
    return NULL;
}

static const char *
set_flags(cmd_parms * cmd, void *CFG, const char *arg)
{
    proxy_content_conf *cfg = CFG;

    if (arg && *arg)
    {
        if (!strcmp(arg, "lowercase"))
            cfg->flags |= NORM_LC;
        else if (!strcmp(arg, "dospath"))
            cfg->flags |= NORM_MSSLASH;
        else if (!strcmp(arg, "reset"))
            cfg->flags |= NORM_RESET;
    }
    return NULL;
}

static const char *
set_events(cmd_parms * cmd, void *CFG, const char *arg)
{
    tattr *attr;
    proxy_content_conf *cfg = CFG;

    if (cfg->events == NULL)
        cfg->events = apr_array_make(cmd->pool, 20, sizeof(tattr));
    attr = apr_array_push(cfg->events);
    attr->val = arg;
    return NULL;
}

static const char *
set_skipto(cmd_parms * cmd, void *CFG, const char *arg)
{
    tattr *attr;
    proxy_content_conf *cfg = CFG;

    if (cfg->skipto == NULL)
        cfg->skipto = apr_array_make(cmd->pool, 4, sizeof(tattr));
    attr = apr_array_push(cfg->skipto);
    attr->val = arg;
    return NULL;
}

static const char *
set_links(cmd_parms * cmd, void *CFG, const char *elt, const char *att)
{
    apr_array_header_t *attrs;
    tattr *attr;
    proxy_content_conf *cfg = CFG;

    if (cfg->links == NULL)
        cfg->links = apr_hash_make(cmd->pool);

    attrs = apr_hash_get(cfg->links, elt, APR_HASH_KEY_STRING);
    if (!attrs)
    {
        attrs = apr_array_make(cmd->pool, 2, sizeof(tattr *));
        apr_hash_set(cfg->links, elt, APR_HASH_KEY_STRING, attrs);
    }
    attr = apr_array_push(attrs);
    attr->val = att;
    return NULL;
}

static const char *
set_extended(cmd_parms *cmd, void *CFG, const char *arg)
{
    proxy_content_conf *cfg = CFG;
    
    if (arg && *arg)
    {
        if (strcasecmp(arg, "styles") == 0 || strcasecmp(arg, "all") == 0)
        {
            cfg->extfix |= EXTFIX_STYLES;
        }
        if (strcasecmp(arg, "scripts") == 0 || strcasecmp(arg, "all") == 0)
        {
            cfg->extfix |= EXTFIX_SCRIPTS;
        }
        if (strcasecmp(arg, "off") == 0)
        {
            cfg->extfix = 0;
        }
    }
    return NULL;
}

static const char *
set_charset_alias(cmd_parms * cmd, void *CFG, const char *charset, const char *alias)
{
    const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (errmsg != NULL)
        return errmsg;
    else if (xmlAddEncodingAlias(charset, alias) == 0)
        return NULL;
    else
        return "Error setting charset alias";
}

static const char *
set_charset_default(cmd_parms * cmd, void *CFG, const char *charset)
{
    proxy_content_conf *cfg = CFG;

    cfg->default_encoding = xmlParseCharEncoding(charset);
    switch (cfg->default_encoding)
    {
        case XML_CHAR_ENCODING_NONE:
            return "Default charset not found";
        case XML_CHAR_ENCODING_ERROR:
            return "Invalid or unsupported default charset";
        default:
            return NULL;
    }
}

static const command_rec proxy_content_cmds[] = {
    AP_INIT_ITERATE("ProxyHTMLStartParse", set_skipto, NULL,
                    RSRC_CONF | ACCESS_CONF,
                    "Ignore anything in front of the first of these elements"),
    AP_INIT_ITERATE("ProxyHTMLEvents", set_events, NULL,
                    RSRC_CONF | ACCESS_CONF, "Strings to be treated as scripting events"),
    AP_INIT_ITERATE2("ProxyHTMLLinks", set_links, NULL,
                     RSRC_CONF | ACCESS_CONF, "Declare HTML Attributes"),
    AP_INIT_RAW_ARGS("ProxyHTMLURLMap", set_urlmap, NULL,
                     RSRC_CONF | ACCESS_CONF, "Map URL From To"),
    AP_INIT_TAKE12("ProxyHTMLDoctype", set_doctype, NULL,
                   RSRC_CONF | ACCESS_CONF, "(HTML|XHTML) [Legacy]"),
    AP_INIT_ITERATE("ProxyHTMLFixups", set_flags, NULL,
                    RSRC_CONF | ACCESS_CONF, "Options are lowercase, dospath"),
    AP_INIT_FLAG("ProxyHTMLMeta", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(proxy_content_conf, metafix),
                 RSRC_CONF | ACCESS_CONF, "Fix META http-equiv elements"),
    AP_INIT_FLAG("ProxyHTMLInterp", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(proxy_content_conf, interp),
                 RSRC_CONF | ACCESS_CONF,
                 "Support interpolation and conditions in URLMaps"),
    AP_INIT_ITERATE("ProxyHTMLExtended", set_extended, NULL,
                    RSRC_CONF | ACCESS_CONF, "Map URLs in Javascript and/or CSS"),
    AP_INIT_FLAG("ProxyHTMLStripComments", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(proxy_content_conf, strip_comments),
                 RSRC_CONF | ACCESS_CONF, "Strip out comments"),
    AP_INIT_FLAG("ProxyHTMLLogVerbose", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(proxy_content_conf, verbose),
                 RSRC_CONF | ACCESS_CONF, "Verbose Logging (use with LogLevel Info)"),
    AP_INIT_TAKE1("ProxyHTMLBufSize", ap_set_int_slot,
                  (void *) APR_OFFSETOF(proxy_content_conf, bufsz),
                  RSRC_CONF | ACCESS_CONF, "Buffer size"),
    AP_INIT_ITERATE2("ProxyHTMLCharsetAlias", set_charset_alias, NULL,
                     RSRC_CONF, "ProxyHTMLCharsetAlias charset alias [more aliases]"),
    AP_INIT_TAKE1("ProxyHTMLCharsetDefault", set_charset_default, NULL,
                  RSRC_CONF | ACCESS_CONF, "Usage: ProxyHTMLCharsetDefault charset"),
    AP_INIT_TAKE1("ProxyHTMLCharsetOut", ap_set_string_slot,
                  (void *) APR_OFFSETOF(proxy_content_conf, charset_out),
                  RSRC_CONF | ACCESS_CONF, "Usage: ProxyHTMLCharsetOut charset"),
    {NULL}
};

static int
mod_proxy_content(apr_pool_t * p, apr_pool_t * p1, apr_pool_t * p2, server_rec * s)
{
    ap_add_version_component(p, VERSION_STRING);
    seek_meta_ctype = ap_pregcomp(p,
                                  "(<meta[^>]*http-equiv[ \t\r\n='\"]*content-type[^>]*>)",
                                  AP_REG_EXTENDED | AP_REG_ICASE);
    seek_charset = ap_pregcomp(p, "charset=([A-Za-z0-9_-]+)", AP_REG_EXTENDED | AP_REG_ICASE);
    seek_meta = ap_pregcomp(p, "<meta[^>]*(http-equiv)[^>]*>", AP_REG_EXTENDED | AP_REG_ICASE);
    seek_content = apr_strmatch_precompile(p, "content", 0);
    memset(&sax, 0, sizeof(htmlSAXHandler));
    sax.startElement = pstartElement;
    sax.endElement = pendElement;
    sax.characters = pcharacters;
    sax.comment = pcomment;
    sax.cdataBlock = pcdata;
    return OK;
}

static void
proxy_content_hooks(apr_pool_t * p)
{
    ap_register_output_filter_protocol("proxy-content", proxy_content_filter,
                                       NULL, AP_FTYPE_RESOURCE,
                                       AP_FILTER_PROTO_CHANGE | AP_FILTER_PROTO_CHANGE_LENGTH);
    ap_hook_post_config(mod_proxy_content, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA proxy_content_module = {
    STANDARD20_MODULE_STUFF,
    proxy_content_config,
    proxy_content_merge,
    NULL,
    NULL,
    proxy_content_cmds,
    proxy_content_hooks
};
