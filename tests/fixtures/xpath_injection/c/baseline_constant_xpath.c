/* Baseline: expression is a compile-time constant.  No taint reaches
 * xmlXPathEvalExpression so no XPATH_INJECTION finding fires. */
#include <libxml/xpath.h>

xmlXPathObjectPtr do_lookup(xmlXPathContextPtr ctx) {
    return xmlXPathEvalExpression((xmlChar *)"//user[@role='admin']", ctx);
}
