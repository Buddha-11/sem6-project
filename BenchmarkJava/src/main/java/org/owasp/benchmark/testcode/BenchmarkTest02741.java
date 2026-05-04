/**
 * OWASP Benchmark Project v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Arpit (added for pipeline testing)
 * @created 2026
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * VULNERABLE: SQL Injection (CWE-89)
 *
 * This servlet reads a username directly from the HTTP request parameter and
 * concatenates it into a SQL query without any sanitization or use of
 * PreparedStatement, making it trivially injectable.
 *
 * This test case was added manually to verify that the CodeQL / agentic
 * pipeline detects and patches newly introduced vulnerabilities.
 */
@WebServlet(value = "/sqli-06/BenchmarkTest02741")
public class BenchmarkTest02741 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        // *** VULNERABLE: user input used directly in SQL without sanitization ***
        String username = request.getParameter("BenchmarkTest02741");

        // Direct string concatenation creates a SQL injection vulnerability.
        // A malicious user can supply: ' OR '1'='1
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";

        try {
            java.sql.Statement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            statement.execute(sql);
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);
        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
            } else throw new ServletException(e);
        }
    } // end doPost
}
