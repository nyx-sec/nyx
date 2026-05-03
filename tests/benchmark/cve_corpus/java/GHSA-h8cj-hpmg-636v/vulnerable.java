// Nyx CVE benchmark fixture.
// CVE:        GHSA-h8cj-hpmg-636v
// Project:    appsmith (appsmithorg/appsmith)
// License:    Apache-2.0
// Advisory:   https://github.com/advisories/GHSA-h8cj-hpmg-636v
// Vulnerable: b142de499faa31b8391bc8dba40daa9519ebac1e
//             app/server/appsmith-interfaces/src/main/java/com/appsmith/external/services/ce/FilterDataServiceCE.java:509-519,625-630
//
// FilterDataServiceCE exposes dropTable(String) which concatenates the
// caller-supplied table name into a "DROP TABLE …;" statement and runs
// it on the in-memory H2 connection via Statement.execute. The advisory
// confirms a reachable code path passes user input through to this
// helper, giving an attacker primary SQL injection on the H2 filter db.
//
// Trims:
//   - imports for AppsmithPlugin / Jackson / commons-lang3 / log4j /
//     SerializationUtils that the dropTable + executeDbQuery slice does
//     not touch (lines 1-40 of upstream).
//   - the ~900 lines of generateTable / generateSchema / generateLogicalQuery
//     / insertReadyData / select-result helpers around the dropTable site,
//     none of which the attacker reaches.
//   - the H2 connection-cache and DriverManager.getConnection setup; the
//     fixture stubs checkAndGetConnection() since the SQLi is in the call
//     to Statement.execute and not the connection bootstrap.
//   - the actual REST controller that reaches dropTable() lives in a
//     separate file in upstream and routes through several plugin layers.
//     The fixture stands in a minimal Servlet-style entry point
//     (HttpServletRequest.getParameter) to model the user-input source;
//     the load-bearing dropTable + executeDbQuery code below is verbatim
//     from upstream.

package com.appsmith.external.services.ce;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class FilterController {
    private final FilterDataServiceCE service = new FilterDataServiceCE();

    public void drop(HttpServletRequest req) {
        String tableName = req.getParameter("tableName");
        service.dropTable(tableName);
    }
}

class FilterDataServiceCE {
    /** Long-lived field; upstream caches the H2 connection across calls. */
    private Connection connection;

    public void dropTable(String tableName) {

        String dropTableQuery = "DROP TABLE " + tableName + ";";

        executeDbQuery(dropTableQuery);
    }

    private void executeDbQuery(String query) {

        try (Statement statement = connection.createStatement()) {
            statement.execute(query);
        } catch (SQLException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
