package com.example.oauth2.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import com.example.oauth2.OAuth2.CustomOAuth2User;
import com.example.oauth2.OAuth2.CustomOAuth2UserService;
import com.example.oauth2.OAuth2.UserOAuth2Service;

@Configuration
@EnableWebSecurity
public class WebSecurity {
    @Autowired
    private CustomOAuth2UserService customOAuthService;

    @Autowired
    private UserOAuth2Service userService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .cors()
                .and()
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/api/**").permitAll()
                .antMatchers("api/auth/login/**", "api/auth/register/**").permitAll()
                .antMatchers("/", "/login.html", "/oauth/**").permitAll()
                .antMatchers("/user").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .loginPage("/login.html")
				.userInfoEndpoint()
					.userService(customOAuthService)
				.and()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                            Authentication authentication) throws IOException, ServletException {
                        System.out.println("AuthenticationSuccessHandler invoked");
                        System.out.println("Authentication name: " + authentication.getName());
                        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

                        userService.processOAuthPostLogin(oauthUser.getEmail());
                        response.sendRedirect("/");
                    }
                })
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .logout(l -> {
                    // TODO: Handle logout
                    l.logoutUrl("/oauth2/logout");
                    l.clearAuthentication(true);
                    l.logoutSuccessHandler((request, response, authentication) -> {
                        response.setStatus(HttpStatus.OK.value());
                    });
                    l.deleteCookies("XSRF-TOKEN", "JSESSIONID");
                });
        return http.build();
    }

    // TODO: handle failed login
    private void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            Exception exception) {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}