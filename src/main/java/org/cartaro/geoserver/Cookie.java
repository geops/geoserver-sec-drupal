package org.cartaro.geoserver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Cookie {
	/**
	 * Sets a cookie according to request parameters
	 * @param request
	 * @param response
	 */
	public void setCookie(HttpServletRequest request, HttpServletResponse response){
		// Set obligatory cookie data
		final String cookieName = request.getParameter("name");
		final String cookieValue = request.getParameter("value");
		javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie(cookieName, cookieValue);
		
		// Optional data is set only when given in request
		final String comment = request.getParameter("comment");
		if(comment!=null){
			cookie.setComment(comment);
		}
		final String domain = request.getParameter("domain");
		if(domain!=null){
			cookie.setDomain(domain);
		}
		final String maxAge = request.getParameter("max-age");
		if(maxAge!=null){
			cookie.setMaxAge(Integer.parseInt(maxAge));
		}
		final String path = request.getParameter("path");
		if(path!=null){
			cookie.setPath(path);
		}
		final String secure = request.getParameter("secure");
		if(secure!=null){
			cookie.setSecure(Boolean.parseBoolean(secure));
		}
		final String version = request.getParameter("cookie-version");
		if(version!=null){
			cookie.setVersion(Integer.parseInt(version));
		}
		
		response.addCookie(cookie);
	}
}
