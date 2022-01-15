package com.jwt.helper;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
//import org.springframework.stereotype.Service;

import com.jwt.model.JwtResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;

//has all the methods for generating token
//validate token
//check token
//util class for JWT
@Component
public class JwtUtil {

	// public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
	// public static final long JWT_TOKEN_VALIDITY = 120000;
	public static final long JWT_TOKEN_VALIDITY = 1000 * 60 * 60 * 10;

	private String secret = "ashishmewada123";

	// retrieve username from jwt token
	public String getUsernameFromToken(String token) {

		return getClaimFromToken(token, Claims::getSubject);
	}

	// retrieve expiration date from jwt token
	public Date getExpirationDateFromToken(String token) {

		return getClaimFromToken(token, Claims::getExpiration);

	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	// for retrieveing any information from token we will need the secret key
	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	// check if the token has expired
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}
	


	// generate token for user
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		byte[] rand = new byte[32];
		String response = new ClaimsHelper().performSafetynetAtt(rand);
		return doGenerateToken(claims, userDetails.getUsername(), response);
	}

	// while creating the token -
	// 1. Define claims of the token, Like Issuer, Subject, and the ID
	// 2. Sign the JWT using the HS512 algorithm and secret key
	// 3. According to JWS Compact
	// Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)

	// Compaction of the JWT to a URL-safe string or create token
	private String doGenerateToken(Map<String, Object> claims, String subject, String safetynetAtt) {

//		//add 32 bytes random value
//		SecureRandom random = new SecureRandom();
//		byte[] values = new byte[32];
//		random.nextBytes(values);
		
//		//add UTC time and date
//		Date currentUtcTime = Date.from(Instant.now());
//		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
//		sdf.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));

		return Jwts.builder().setClaims(claims)
				.setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
				.signWith(SignatureAlgorithm.HS512, secret)
				.claim("safetynetAtt", TextCodec.BASE64URL.encode(safetynetAtt))
				//.claim("Random val", values)
				//.claim("UTC", sdf.format(currentUtcTime))
				//.claim("randonNo", TextCodec.BASE64.encode(serverRandomNo))
				.claim("UTC", new ClaimsHelper().GetUTCdatetime())
				.claim("Random val", new ClaimsHelper().getRandomNo())
				.compact();
	
	}

	// validation token
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

}
