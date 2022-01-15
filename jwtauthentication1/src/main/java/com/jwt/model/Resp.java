package com.jwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Resp {
	
	//public static final String Jwts = null;
	byte[] randV;
	String utc;
	String token;
	
}
