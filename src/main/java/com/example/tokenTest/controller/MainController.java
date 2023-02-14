package com.example.tokenTest.controller;

import com.example.tokenTest.dto.LoginDto;
import com.example.tokenTest.security.JWTUtils;
import com.example.tokenTest.security.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class MainController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private UserDetailsService jwtInMemoryUserDetailsService;

    @GetMapping("/")
    public String test(){
        return "Hello World";
    }

    @PostMapping("/getToken")
    public String getJWTToken(@RequestBody LoginDto loginDto){
        try{
            final Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword()));
//            SecurityContextHolder.getContext().setAuthentication(authentication);

            final UserDetails userDetails = jwtInMemoryUserDetailsService.loadUserByUsername(loginDto.getUsername());

            final String token = jwtUtils.generateToken(userDetails.getUsername());

            return token;

        }catch (Exception e){
            return "Invalid username and password";
        }
    }
}
