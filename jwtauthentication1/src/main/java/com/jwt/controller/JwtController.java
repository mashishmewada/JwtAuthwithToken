package com.jwt.controller;

import java.io.UnsupportedEncodingException;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.deser.Deserializers.Base;
import com.jwt.helper.JwtUtil;
import com.jwt.model.JwtRequest;
import com.jwt.model.JwtResponse;
import com.jwt.services.customUserDetailsService;

@RestController
public class JwtController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private customUserDetailsService customUserDetailsService;

	@Autowired
	private JwtUtil jwtUtil;

	@PostMapping("/token")
	public ResponseEntity<?> generateToken(@RequestBody JwtRequest jwtRequest) throws Exception {
		// System.out.println(jwtRequest);
		try {

			this.authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));

		} catch (UsernameNotFoundException e) {
			e.printStackTrace();
			throw new Exception("Invalid username or password");
		} catch (BadCredentialsException e) {
			e.printStackTrace();
			throw new Exception("Bad Credentials");
		}

		// fine area...
		UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(jwtRequest.getUsername());

		// token generate
		String token = this.jwtUtil.generateToken(userDetails);
		System.out.println("JWT " + token);

		// return token using JSON
		return ResponseEntity.ok(new JwtResponse(token));
	}

	@PostMapping(value = "/token/decode", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public String decodeToken(@RequestBody String token) throws UnsupportedEncodingException {

		// decode header.payload.signingkey
		byte[] decoded = Base64.decodeBase64(token);
		// System.out.println("Base 64 Decoded String : " + new String(decoded));
		return new String(decoded);

		// decode payload
		// String payload = token.split("\\.")[1];
		// return new String(Base64.decodeBase64(payload), "UTF-8");

	}

}
