package com.ibm.security.appscan.altoromutual.api;

import javax.annotation.security.PermitAll;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.ibm.security.appscan.altoromutual.security.SecurityUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

@Path("/logout")
public class LogoutAPI extends AltoroAPI{

	@GET
	@PermitAll
	public Response doLogOut(@Context HttpServletRequest request){
		
		try{
			String authHeader = request.getHeader("Authorization");
			if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
				SecurityUtil.revokeApiToken(authHeader.substring(7).trim());
			}
			if (request.getSession(false) != null) {
				request.getSession().invalidate();
			} else {
				request.getSession(true).removeAttribute(ServletUtil.SESSION_ATTR_USER);
			}
			String response="{\"LoggedOut\" : \"True\"}";
			return Response.status(Response.Status.OK).entity(response).type(MediaType.APPLICATION_JSON_TYPE).build();}
		catch(Exception e){
			String response = "{\"Error \": \"Unknown error encountered\"}";
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
		}
	}
}
