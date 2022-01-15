package com.jwt.services;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class customUserDetailsService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		
		if (userName.equals("Ashish")) 
		{
			return new User("Ashish", "Ashish123", new ArrayList<>());
		}else {
			throw new UsernameNotFoundException("user not found !!");
		}
		
	}

}
