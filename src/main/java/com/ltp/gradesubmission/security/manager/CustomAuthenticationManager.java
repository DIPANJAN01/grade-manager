package com.ltp.gradesubmission.security.manager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.ltp.gradesubmission.entity.User;
import com.ltp.gradesubmission.service.UserService;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {

    private UserService userServiceImpl;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("bAD Cred");
        User user = userServiceImpl.getUser(authentication.getName());
        if (!bCryptPasswordEncoder.matches(authentication.getCredentials().toString(), user.getPassword())) {
            System.out.println("bAD Cred");
            throw new BadCredentialsException("You provided an incorrect password.");
        }

        System.out.println("not bAD Cred");
        return new UsernamePasswordAuthenticationToken(authentication.getName(), user.getPassword());
    }
}
