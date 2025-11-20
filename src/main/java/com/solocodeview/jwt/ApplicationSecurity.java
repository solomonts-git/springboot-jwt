package com.solocodeview.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class ApplicationSecurity {

	@Autowired private UserRepository userRepo;
	@Autowired private JwtTokenFilter jwtTokenFilter;
	
	@Bean
	 UserDetailsService userDetailsService() {
		return new UserDetailsService() {
			
			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				return userRepo.findByEmail(username)
						.orElseThrow(
								() -> new UsernameNotFoundException("User " + username + " not found")
								);
			}
		};
	}

	@Bean
	 PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	 AuthenticationManager authenticationManger(
			AuthenticationConfiguration authConfig) throws Exception{
		return authConfig.getAuthenticationManager();
	}
	
	@Bean
	 SecurityFilterChain configure(HttpSecurity http) throws Exception{
		http.csrf(csrf -> csrf.disable());
		http.sessionManagement(
				sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				);
		http.authorizeHttpRequests(
				authorizeRequests -> authorizeRequests.requestMatchers(
						"/auth/login","/docs/**","/users"
						).permitAll()
						.anyRequest().authenticated()
				);
		http.exceptionHandling(exceptionHandling -> 
			exceptionHandling.authenticationEntryPoint( 
		    		 (request, response, ex) -> {
		    			 response.sendError(
		    					 HttpServletResponse.SC_UNAUTHORIZED,
		    					 ex.getMessage()
		    					 );
		    		 }
		    		 )
				);
		
		http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
		    		
		return http.build();
	}
}

