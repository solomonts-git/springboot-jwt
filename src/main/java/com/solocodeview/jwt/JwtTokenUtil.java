package com.solocodeview.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.sql.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenUtil {

	private static final long EXPIRE_DURATION = 24*60*60*1000;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);
	
	@Value("${app.jwt.secret")
	private String SECRET_KEY;
	
	public String generateAccessToken(User user) {

	    Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

	    return Jwts.builder()
	            .subject(user.getId() + "," + user.getEmail())
	            .issuer("Solocodeview")
	            .issuedAt(new java.util.Date())
	            .expiration(new Date(System.currentTimeMillis() + EXPIRE_DURATION))
	            .signWith(key)   // ✔ NEW SYNTAX
	            .compact();
	}
	
	
	
	public boolean validateAccessToken(String token) {
	    try {
	        SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

	        Jwts.parser()
	                .verifyWith(key)                 
	                .build()
	                .parseSignedClaims(token);       

	        return true;

	    } catch (ExpiredJwtException ex) {
	        LOGGER.error("JWT expired", ex.getMessage());
	    } catch (IllegalArgumentException ex) {
	        LOGGER.error("Token is null, empty or only whitespace", ex.getMessage());
	    } catch (MalformedJwtException ex) {
	        LOGGER.error("JWT is invalid", ex.getMessage());
	    } catch (UnsupportedJwtException ex) {
	        LOGGER.error("JWT is not supported", ex.getMessage());
	    } 

	    return false;
	}
	
	public String getSubject(String token) {
		return parseClaims(token).getSubject();
	} 
	
	private Claims parseClaims(String token) {
		  SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

		return Jwts.parser()
				 .verifyWith(key)
				 .build()
				 .parseSignedClaims(token)
				 .getPayload();
	}
	
	


}
