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
 * VULNERABLE: Reflected Cross-Site Scripting (CWE-79)
 *
 * User-supplied input is read from a request parameter and written directly
 * into the HTTP response without HTML encoding. An attacker can supply:
 *   ?BenchmarkTest02743=&lt;script&gt;alert(1)&lt;/script&gt;
 *
 * FIX: wrap the output with
 *   org.owasp.esapi.ESAPI.encoder().encodeForHTML(param)
 * before writing it to the response.
 */
@WebServlet(value = "/xss-00/BenchmarkTest02743")
public class BenchmarkTest02743 extends HttpServlet {

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

        String param = request.getParameter("BenchmarkTest02743");

        response.setHeader("X-XSS-Protection", "0");

        // VULNERABLE: param is written directly without encodeForHTML()
        response.getWriter().println("<p>Hello, " + param + "</p>");
    }
}
