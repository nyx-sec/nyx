// Phase 15 — Java JDBC raw-string concat SQLi positive.
// `Statement.executeQuery` is a flat SQL_QUERY sink in
// `labels/java.rs`; concatenated `request.getParameter` value flows
// directly into the SQL string with no parameterisation.
package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqliJavaConcat {
    public ResultSet lookup(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:db");
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
