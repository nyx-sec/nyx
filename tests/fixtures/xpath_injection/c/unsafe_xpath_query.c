/* Unsafe: tainted env-string passed straight as the XPath expression to
 * xmlXPathEvalExpression.  XPATH_INJECTION fires on the expression arg. */
#include <libxml/xpath.h>
#include <stdlib.h>

xmlXPathObjectPtr do_lookup(xmlXPathContextPtr ctx) {
    char *user_expr = getenv("USER_EXPR");
    return xmlXPathEvalExpression((xmlChar *)user_expr, ctx);
}
