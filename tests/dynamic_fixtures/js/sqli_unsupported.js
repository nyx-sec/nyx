// SQL injection — unsupported fixture.
// The entry point accepts an HTTP request object, not a plain string.
// HarnessSpec derivation will map this to HttpBody slot (unsupported by JS emitter).
// Entry: handleRequest(req)  Cap: SQL_QUERY
// Expected verdict: Unsupported (EntryKindUnsupported or ConfidenceTooLow)

class UserRepository {
    findUser(req) {
        const name = req && req.body && req.body.name;
        const query = "SELECT * FROM users WHERE name='" + name + "'";
        return query;
    }
}

module.exports = { UserRepository };
