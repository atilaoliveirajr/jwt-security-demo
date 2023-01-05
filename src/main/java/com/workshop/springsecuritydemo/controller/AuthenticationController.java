package com.workshop.springsecuritydemo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.workshop.springsecuritydemo.config.JwtUtils;
import com.workshop.springsecuritydemo.dao.UserDao;
import com.workshop.springsecuritydemo.dto.AuthenticationRequest;

@RestController
@RequestMapping("api/v1/auth")
public class AuthenticationController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDao userDao;
	
	@Autowired
	private JwtUtils jwtUtils;
	
	@PostMapping("/authenticate")
	public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		final UserDetails user = userDao.findUserByEmail(request.getEmail());
		if(user != null ) {
			return ResponseEntity.ok(jwtUtils.generateToken(user));
		}
		
		return ResponseEntity.status(400).body("Some error has occurred");
	}
}
