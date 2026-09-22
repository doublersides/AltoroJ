package com.ibm.security.appscan.altoromutual.filter;

import java.io.IOException;

import javax.annotation.security.PermitAll;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import com.ibm.security.appscan.altoromutual.security.SecurityUtil;

public class ApiAuthFilter implements ContainerRequestFilter {

	@Context 
	private ResourceInfo resourceInfo;
	
	private static final String NOT_LOGGED_IN_ERROR = "loggedIn=false"+System.lineSeparator()+"Please log in first";
	
	private static final String AUTHENTICATION_SCHEME = "Bearer";
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		
		java.lang.reflect.Method method = resourceInfo.getResourceMethod(); 
		
		if(method.isAnnotationPresent(PermitAll.class)) {
			return;
		}
	
		//Get request headers 
		final MultivaluedMap<String, String> headers = requestContext.getHeaders();
		final java.util.List<String> authorization = headers.get("Authorization");
			
		//If there's no authorization present, deny request 
		if(authorization==null || authorization.isEmpty()){
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
		            .entity(NOT_LOGGED_IN_ERROR).build());
            return;
		}
			
		String authHeader = authorization.get(0);
		if (authHeader == null || !authHeader.regionMatches(true, 0, AUTHENTICATION_SCHEME + " ", 0, AUTHENTICATION_SCHEME.length() + 1)) {
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
		            .entity(NOT_LOGGED_IN_ERROR).build());
	           return;
		}

		String accessToken = authHeader.substring(AUTHENTICATION_SCHEME.length() + 1).trim();
		String username = SecurityUtil.resolveApiToken(accessToken);
		if (username == null) {
			requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
		            .entity(NOT_LOGGED_IN_ERROR).build());
		}
	}
}
