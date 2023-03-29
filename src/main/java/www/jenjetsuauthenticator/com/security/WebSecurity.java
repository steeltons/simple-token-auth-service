package www.jenjetsuauthenticator.com.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurity{
	
	private final UserDetailsServiceImpl userDetailsSerivce;
	private final AccessTokenEntryPoint accessTokenEntryPoint;
	public WebSecurity(UserDetailsServiceImpl userDetailsSerivce,
					   AccessTokenEntryPoint accessTokenEntryPoint) {
		this.userDetailsSerivce = userDetailsSerivce;
		this.accessTokenEntryPoint = accessTokenEntryPoint;
	}
	
	@Bean
	@Autowired
	public SecurityFilterChain configure(HttpSecurity http) throws Exception{
		return http.cors().and().csrf().disable()
			.exceptionHandling().authenticationEntryPoint(accessTokenEntryPoint)
			.and()
			.authorizeRequests()
			.antMatchers(HttpMethod.POST, "/users/sing-up").permitAll()
			.antMatchers("/api/auth/**").permitAll()
			.antMatchers("/h2-console/**")	.permitAll()
			.anyRequest().authenticated()
			.and()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilterBefore(accessTokenFilter(), UsernamePasswordAuthenticationFilter.class)
			.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}
	
	@Bean
	public AccessTokenFilter accessTokenFilter() {
		return new AccessTokenFilter();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class)
				   .userDetailsService(userDetailsSerivce)
				   .passwordEncoder(passwordEncoder())
				   .and()
				   .build();
	}
}
