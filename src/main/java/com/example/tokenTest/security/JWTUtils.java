package com.example.tokenTest.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
public class JWTUtils {

    @Value("${jwt.auth.secret_key}")
    private String secretKey;

    @Value("${jwt.auth.expires_in}")
    private Integer expiresIn;

    public String generateToken(String userName) {
        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    private Date generateExpirationDate(){
        return new Date(new Date().getTime() + expiresIn*10000);
    }

    private Claims getAllClaimsFromToken (String token){
        Claims claims;
        try{
            claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();
        }catch (Exception e){
            claims = null;
        }

        return claims;
    }

    public String generateUsernameFromToken(String token){
        String username;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            username = claims.getSubject();
        }catch (Exception e) {
            username = null;
        }
        return username;
    }

    public  Boolean isTokenExpired(String token){
        Date expiredDate = getExpirationDate(token);
        return expiredDate.before(new Date());
    }

    private Date getExpirationDate(String token){
        Date expireDate;
        try {
            final Claims claims = this.getAllClaimsFromToken(token);
            expireDate = claims.getExpiration();
        }catch (Exception e){
            expireDate = null;
        }
        return expireDate;
    }

    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = generateUsernameFromToken(token);
        return ( username != null &&
                username.equals(userDetails.getUsername()) &&
                !isTokenExpired(token)
                );
    }

    public String getToken(HttpServletRequest request){
        String authHeader = getAuthHeaderFromHeader(request);
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;
    }

    public String getAuthHeaderFromHeader(HttpServletRequest request){
        return request.getHeader("x-Authorization");
    }
}
