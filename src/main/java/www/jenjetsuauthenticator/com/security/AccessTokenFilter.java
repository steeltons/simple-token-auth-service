package www.jenjetsuauthenticator.com.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.slf4j.Slf4j;
import www.jenjetsuauthenticator.com.entity.JenjetsuUser;

@Slf4j
public class AccessTokenFilter extends OncePerRequestFilter{
	@Autowired
	private JWTHelper helper;
	@Autowired
	private UserDetailsServiceImpl detailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			Optional<String> token = parseAccessTokenFromRequest(req);
			if(token.isPresent() && helper.validateAccessToken(token.get())) {
				Long userId = helper.getUserIdFromAccessToken(token.get());
				JenjetsuUser user = detailsService.findById(userId);
				UsernamePasswordAuthenticationToken upat = 
												new UsernamePasswordAuthenticationToken(user, null , new ArrayList<>());
				upat.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
				SecurityContextHolder.getContext().setAuthentication(upat);
			}
		} catch(Exception e) {
			log.error("cannot be authenticated", e);
		}
		filterChain.doFilter(req, resp);
	}

	private Optional<String> parseAccessTokenFromRequest(HttpServletRequest req){
		String authHeader = req.getHeader(helper.HEADER_STRING);
		if(StringUtils.hasText(authHeader) && authHeader.startsWith(helper.TOKEN_PREFIX)) {
			return Optional.of(authHeader.replace(helper.TOKEN_PREFIX, ""));
		}
		return Optional.empty();
	}
}
