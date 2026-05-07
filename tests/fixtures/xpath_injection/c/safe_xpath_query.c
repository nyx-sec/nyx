/* Safe: project-local sanitize_xpath (matches the developer-named
 * `sanitize_*` Sanitizer rule) clears caps on the user value before it
 * reaches xmlXPathEvalExpression. */
#include <libxml/xpath.h>
#include <stdlib.h>

extern char *sanitize_xpath(const char *raw);

xmlXPathObjectPtr do_lookup(xmlXPathContextPtr ctx) {
    char *user_expr = getenv("USER_EXPR");
    char *safe = sanitize_xpath(user_expr);
    return xmlXPathEvalExpression((xmlChar *)safe, ctx);
}
