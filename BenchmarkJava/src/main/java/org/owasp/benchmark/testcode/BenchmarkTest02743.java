package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.esapi.ESAPI;

/**
 * FIXED: Reflected Cross-Site Scripting (CWE-79)
 *
 * User-supplied input from a request parameter flows into the HTTP response
 * body with HTML encoding, preventing script injection.
 *
 * Attack: ?BenchmarkTest02743=&lt;script&gt;alert(1)&lt;/script&gt;
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

        String safe = ESAPI.encoder().encodeForHTML(param);
        response.getWriter().println("<p>Hello, " + safe + "</p>");
    }
}
