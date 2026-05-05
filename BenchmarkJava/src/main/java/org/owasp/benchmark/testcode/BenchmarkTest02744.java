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
 * VULNERABLE: Path Traversal / Directory Traversal (CWE-22)
 *
 * The servlet reads a filename from a request parameter and opens that file
 * inside TESTFILES_DIR without stripping or canonicalising path components.
 * An attacker can supply: ../../etc/passwd  to escape the intended directory.
 *
 * Added manually to validate that the CodeQL / agentic pipeline correctly
 * detects path-traversal vulnerabilities in newly committed files.
 */
@WebServlet(value = "/pathtraver-00/BenchmarkTest02744")
public class BenchmarkTest02744 extends HttpServlet {

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

        // *** VULNERABLE: user input used as a file path without canonicalisation ***
        String param = request.getParameter("BenchmarkTest02744");

        // Directly concatenating user input — allows ../../../etc/passwd traversal
        String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(new java.io.File(fileName));
            byte[] b = new byte[1000];
            int size = fis.read(b);
            response.getWriter()
                    .println(
                            "The beginning of file: '"
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName)
                                    + "' is:\n\n"
                                    + org.owasp.esapi.ESAPI.encoder()
                                            .encodeForHTML(new String(b, 0, size)));
        } catch (Exception e) {
            System.out.println("Couldn't open FileInputStream on file: '" + fileName + "'");
            response.getWriter()
                    .println(
                            "Problem getting FileInputStream: "
                                    + org.owasp.esapi.ESAPI.encoder()
                                            .encodeForHTML(e.getMessage()));
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    // ignored
                }
            }
        }
    }
}
