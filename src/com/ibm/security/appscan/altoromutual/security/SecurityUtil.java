package com.ibm.security.appscan.altoromutual.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.http.HttpSession;

/**
 * Shared helpers for password hashing, CSRF tokens, and API bearer tokens.
 */
public final class SecurityUtil {

	public static final String CSRF_TOKEN_ATTR = "csrfToken";
	public static final String CSRF_PARAM = "csrfToken";
	public static final String CSRF_HEADER = "X-CSRF-Token";

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static final Map<String, String> API_TOKENS = new ConcurrentHashMap<String, String>();
	private static final long API_TOKEN_TTL_MS = 8L * 60L * 60L * 1000L;
	private static final Map<String, Long> API_TOKEN_EXPIRY = new ConcurrentHashMap<String, Long>();

	private SecurityUtil() {
	}

	public static String hashPassword(String password) {
		if (password == null) {
			return null;
		}
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
			StringBuilder hex = new StringBuilder(hash.length * 2);
			for (byte b : hash) {
				hex.append(String.format("%02x", b));
			}
			return hex.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}

	public static boolean passwordsMatch(String plaintext, String storedHash) {
		if (plaintext == null || storedHash == null) {
			return false;
		}
		String candidate = hashPassword(plaintext);
		return constantTimeEquals(candidate, storedHash);
	}

	private static boolean constantTimeEquals(String a, String b) {
		if (a == null || b == null || a.length() != b.length()) {
			return false;
		}
		int result = 0;
		for (int i = 0; i < a.length(); i++) {
			result |= a.charAt(i) ^ b.charAt(i);
		}
		return result == 0;
	}

	public static String generateToken() {
		byte[] bytes = new byte[32];
		SECURE_RANDOM.nextBytes(bytes);
		StringBuilder hex = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			hex.append(String.format("%02x", b));
		}
		return hex.toString();
	}

	public static String getOrCreateCsrfToken(HttpSession session) {
		if (session == null) {
			return null;
		}
		String token = (String) session.getAttribute(CSRF_TOKEN_ATTR);
		if (token == null || token.length() == 0) {
			token = generateToken();
			session.setAttribute(CSRF_TOKEN_ATTR, token);
		}
		return token;
	}

	public static boolean isValidCsrfToken(HttpSession session, String provided) {
		if (session == null || provided == null || provided.length() == 0) {
			return false;
		}
		String expected = (String) session.getAttribute(CSRF_TOKEN_ATTR);
		return expected != null && constantTimeEquals(expected, provided);
	}

	public static String issueApiToken(String username) {
		purgeExpiredApiTokens();
		String token = generateToken();
		API_TOKENS.put(token, username);
		API_TOKEN_EXPIRY.put(token, Long.valueOf(System.currentTimeMillis() + API_TOKEN_TTL_MS));
		return token;
	}

	public static String resolveApiToken(String token) {
		if (token == null || token.length() == 0) {
			return null;
		}
		purgeExpiredApiTokens();
		Long expiry = API_TOKEN_EXPIRY.get(token);
		if (expiry == null || expiry.longValue() < System.currentTimeMillis()) {
			revokeApiToken(token);
			return null;
		}
		return API_TOKENS.get(token);
	}

	public static void revokeApiToken(String token) {
		if (token == null) {
			return;
		}
		API_TOKENS.remove(token);
		API_TOKEN_EXPIRY.remove(token);
	}

	public static void revokeApiTokensForUser(String username) {
		if (username == null) {
			return;
		}
		Iterator<Map.Entry<String, String>> it = API_TOKENS.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, String> entry = it.next();
			if (username.equals(entry.getValue())) {
				API_TOKEN_EXPIRY.remove(entry.getKey());
				it.remove();
			}
		}
	}

	private static void purgeExpiredApiTokens() {
		long now = System.currentTimeMillis();
		Iterator<Map.Entry<String, Long>> it = API_TOKEN_EXPIRY.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, Long> entry = it.next();
			if (entry.getValue().longValue() < now) {
				API_TOKENS.remove(entry.getKey());
				it.remove();
			}
		}
	}

	/**
	 * Restricts dynamic includes to a simple filename under /static (no path traversal).
	 */
	public static boolean isSafeStaticContent(String content) {
		if (content == null || content.length() == 0) {
			return false;
		}
		if (content.indexOf("..") >= 0 || content.indexOf('\\') >= 0 || content.indexOf('/') >= 0) {
			return false;
		}
		return content.matches("^[A-Za-z0-9_\\-\\.]+\\.(htm|html)$");
	}
}
