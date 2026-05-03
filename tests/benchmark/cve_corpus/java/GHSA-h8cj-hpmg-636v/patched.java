// Nyx CVE benchmark fixture (patched).
// CVE:        GHSA-h8cj-hpmg-636v
// Project:    appsmith (appsmithorg/appsmith)
// License:    Apache-2.0
// Advisory:   https://github.com/advisories/GHSA-h8cj-hpmg-636v
// Patched:    c8023ba4b3b54204ff3309c9e5c33664ad15ba32
//             app/server/appsmith-interfaces/src/main/java/com/appsmith/external/services/ce/FilterDataServiceCE.java:60-65,632-647
//
// Patched dropTable() now calls validateFilterTempTableName(tableName)
// before constructing the SQL string. The validator rejects any input
// that does not match `^tbl_[A-Z]{16}$`, the exact shape produced by
// FilterDataServiceCE.generateTable() (`tbl_` + 16 random uppercase
// alphabetics). Anything caller-supplied that is not a real generated
// table name throws and SQL never runs.
//
// Trims:
//   - same as vulnerable.java (imports / generateTable scaffolding /
//     connection-cache helpers).
//   - AppsmithPluginException replaced with java.lang.IllegalArgumentException
//     to keep the fixture self-contained; the upstream throw still rejects
//     the request before it can reach SQL.
//   - StringUtils.isBlank() inlined as `tableName == null || tableName.isBlank()`
//     to keep the regex-allowlist as the load-bearing sanitiser without
//     pulling in commons-lang3.
//
// Patched-fix simplification: the entry-point Servlet controller and
// the dropTable + executeDbQuery code are kept verbatim from the
// surrounding upstream context; the validator + Pattern.compile are
// copied byte-for-byte from the patched commit.

package com.appsmith.external.services.ce;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

class FilterController {
    private final FilterDataServiceCE service = new FilterDataServiceCE();

    public void drop(HttpServletRequest req) {
        String tableName = req.getParameter("tableName");
        service.dropTable(tableName);
    }
}

class FilterDataServiceCE {
    /**
     * Names produced by {@link #generateTable(Map)}: {@code tbl_} plus 16 alphabetic characters (see
     * {@link RandomStringUtils#randomAlphabetic(int)} + uppercase). Used to reject untrusted input in dynamic SQL.
     */
    private static final Pattern FILTER_TEMP_TABLE_NAME_PATTERN = Pattern.compile("^tbl_[A-Z]{16}$");

    public void dropTable(String tableName) {
        validateFilterTempTableName(tableName);

        String dropTableQuery = "DROP TABLE " + tableName + ";";

        executeDbQuery(dropTableQuery);
    }

    private static void validateFilterTempTableName(String tableName) {
        if (tableName == null || tableName.isBlank()
                || !FILTER_TEMP_TABLE_NAME_PATTERN.matcher(tableName).matches()) {
            throw new IllegalArgumentException("Invalid filter temporary table name");
        }
    }

    /** Long-lived field; upstream caches the H2 connection across calls. */
    private Connection connection;

    private void executeDbQuery(String query) {

        try (Statement statement = connection.createStatement()) {
            statement.execute(query);
        } catch (SQLException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
