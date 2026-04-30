// DATA_EXFIL safe: plain user input echoed into a fetch() body must not
// fire. The user already controls req.body.message; surfacing it back
// into the outbound payload is not a cross-boundary disclosure.
function forwardUserMessage(req) {
    var message = req.body.message;
    fetch('/forward', {
        method: 'POST',
        body: message,
    });
}
