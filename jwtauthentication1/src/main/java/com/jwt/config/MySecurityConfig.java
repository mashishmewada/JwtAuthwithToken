package com.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.jwt.services.customUserDetailsService;

@Configuration
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private customUserDetailsService customUserDetailsService;

	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;

	@Autowired
	private JwtAuthenticationEntryPoint entrypoint;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
			.csrf().disable()
			.cors().disable()
			.authorizeRequests()
			.antMatchers("/token").permitAll()
			.anyRequest().authenticated()
			.and()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.exceptionHandling().authenticationEntryPoint(entrypoint);

		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

	}

	// over
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(customUserDetailsService);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();

	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {

		return super.authenticationManagerBean();

	}

}
