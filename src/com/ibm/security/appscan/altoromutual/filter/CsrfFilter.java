package com.ibm.security.appscan.altoromutual.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.ibm.security.appscan.altoromutual.security.SecurityUtil;

/**
 * Requires a valid CSRF token on state-changing browser requests.
 * REST API calls under /api/ are exempt (authenticated via bearer token).
 */
public class CsrfFilter implements Filter {

	public void init(FilterConfig filterConfig) throws ServletException {
	}

	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		if (!(req instanceof HttpServletRequest) || !(resp instanceof HttpServletResponse)) {
			chain.doFilter(req, resp);
			return;
		}

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String method = request.getMethod();
		String path = request.getRequestURI();
		String context = request.getContextPath();
		if (context != null && path.startsWith(context)) {
			path = path.substring(context.length());
		}

		if (path.startsWith("/api/") || path.equals("/api")) {
			chain.doFilter(req, resp);
			return;
		}

		if ("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)
				|| "OPTIONS".equalsIgnoreCase(method)) {
			HttpSession session = request.getSession(true);
			SecurityUtil.getOrCreateCsrfToken(session);
			chain.doFilter(req, resp);
			return;
		}

		HttpSession session = request.getSession(false);
		String provided = request.getParameter(SecurityUtil.CSRF_PARAM);
		if (provided == null || provided.length() == 0) {
			provided = request.getHeader(SecurityUtil.CSRF_HEADER);
		}

		if (!SecurityUtil.isValidCsrfToken(session, provided)) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing CSRF token");
			return;
		}

		chain.doFilter(req, resp);
	}

	public void destroy() {
	}
}
