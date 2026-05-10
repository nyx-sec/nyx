package org.openmrs.util.databasechange;

import java.sql.SQLException;
import java.sql.Statement;
import java.sql.ResultSet;

public class ChangeSet {
    private int getInt(JdbcConnection connection, String sql) {
        Statement stmt = null;
        int result = 0;
        try {
            stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                result = rs.getInt(1);
            }
        } catch (SQLException e) {
            // ignored for fixture
        } finally {
            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException e) {
                }
            }
        }
        return result;
    }

    private void runUpdate(JdbcConnection connection, String sql) throws SQLException {
        Statement statement = connection.createStatement();
        statement.executeUpdate(sql);
        statement.close();
    }

    private void runChained(JdbcConnection connection, String sql) throws SQLException {
        Statement stmt = connection.unwrap().createStatement();
        stmt.executeQuery(sql);
    }

    interface JdbcConnection {
        Statement createStatement() throws SQLException;
        JdbcConnection unwrap() throws SQLException;
    }
}
