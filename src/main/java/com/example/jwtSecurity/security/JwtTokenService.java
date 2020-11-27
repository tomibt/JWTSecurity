package com.example.jwtSecurity.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Component;

import com.example.jwtSecurity.repository.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenService {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;
	
	@Value("${tokenExpirationTime}")
	Long expirationTime;
	
	@Value("${tokenSecret}")
	String secret;

	String CLAIM_USER_ID = "uid";
	String CLAIM_USER_ROLE = "role";

	public String generate(Long userId, String username, String role) {
		Claims customClaims = Jwts.claims();
		customClaims.put(CLAIM_USER_ID, userId);
		customClaims.put(CLAIM_USER_ROLE, role);

		String accessToken = generateToken(customClaims, username, new Date(), getExpirationDate(expirationTime), secret);

		return accessToken;

	}

	private Date getExpirationDate(Long validityMiliseconds) {
		if (validityMiliseconds == -1) {
			return null;
		}
		return new Date(System.currentTimeMillis() + validityMiliseconds);
	}

	private String generateToken(Claims customClaims, String username, Date issuedAt, Date expiration, String secret) {
		return Jwts.builder().setHeaderParam(JwsHeader.TYPE, JwsHeader.JWT_TYPE).setClaims(customClaims)
				.setSubject(username).setIssuedAt(issuedAt).setExpiration(expiration)
				.signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret))).compact();
	}

}
