package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.entity.User;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Optional;

// 시큐리티가 filter 가지고 있는 데 그 필터중에 BasicAuthenticationFilter라는 것이 있음.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 권한이나 인증이 필요한 특정 주소를 요청했을 때 필터를 무조건 타게 되어있음
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요함.");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);


        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            System.out.println("11111");
            chain.doFilter(request, response);
            return;
        } else {
            
            String jwtToken = jwtHeader.replace("Bearer ", "");


            Long userId =
                    JWT.require(Algorithm.HMAC512("cos"))
                    .build().verify(jwtToken).getClaim("userId").asLong();

            if (userId != null) {

                System.out.println("22222");

                Optional<User> user = userRepository.findById(userId);

                System.out.println("user.get() = " + user.get());
                PrincipalDetails principalDetails = new PrincipalDetails(user.get());
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);


                chain.doFilter(request, response);
            }
        }

    }
}
