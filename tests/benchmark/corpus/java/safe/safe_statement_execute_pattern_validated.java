// Regression guard for GHSA-h8cj-hpmg-636v patched-form recognition:
// the Java `Pattern.matcher(value).matches()` chain is recognised as a
// regex allowlist validator (in `src/taint/path_state.rs`), AND the
// short-circuit cond chain (`x == null || x.isBlank() || !p.matcher(x).matches()`)
// preserves the validation through the implicit-return path so the
// helper-summary `validated_params_to_return` lift suppresses the
// downstream `Statement.execute(query)` SQL_QUERY sink.
//
// Pins that the patched form does NOT fire `taint-unsanitised-flow`.
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;

class FilterServicePatched {
    private static final Pattern FILTER_TEMP_TABLE_NAME_PATTERN = Pattern.compile("^tbl_[A-Z]{16}$");
    private Connection connection;

    public void drop(HttpServletRequest req) {
        String tableName = req.getParameter("tableName");
        dropTable(tableName);
    }

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

    private void executeDbQuery(String query) {
        try (Statement statement = connection.createStatement()) {
            statement.execute(query);
        } catch (SQLException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
