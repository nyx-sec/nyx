// Regression guard for GHSA-h8cj-hpmg-636v engine fixes:
//   1. createStatement → DatabaseConnection in Java constructor_type
//      (`src/ssa/type_facts.rs`).
//   2. DatabaseConnection.execute as SQL_QUERY sink in Java labels
//      (`src/labels/java.rs`).
//   3. Helper-summary type-facts threading through extract_ssa_func_summary
//      (`src/taint/ssa_transfer/summary_extract.rs`).
//   4. push_condition_node populating taint.uses so short-circuit cond
//      branches intern their condition variables for branch narrowing
//      (`src/cfg/conditions.rs`).
//
// Pins that an Appsmith-style SQLi via `Statement.execute(query)` through
// a cross-function helper detects.  Same flow shape as the real CVE
// fixture but reduced to one file with no patched/safe sibling — the
// safe counterpart lives at safe_statement_execute_pattern_validated.java.
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class FilterServiceVulnerable {
    private Connection connection;

    public void drop(HttpServletRequest req) {
        String tableName = req.getParameter("tableName");
        dropTable(tableName);
    }

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
