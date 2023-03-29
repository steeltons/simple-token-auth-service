package www.jenjetsuauthenticator.com.restController;

import javax.transaction.Transactional;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import www.jenjetsuauthenticator.com.dto.LoginDTO;
import www.jenjetsuauthenticator.com.dto.TokenDTO;
import www.jenjetsuauthenticator.com.entity.JenjetsuUser;
import www.jenjetsuauthenticator.com.entity.RefreshToken;
import www.jenjetsuauthenticator.com.entity.SingupDTO;
import www.jenjetsuauthenticator.com.repositiry.RefreshTokenRepository;
import www.jenjetsuauthenticator.com.repositiry.UserRepository;
import www.jenjetsuauthenticator.com.security.JWTHelper;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	private AuthenticationManager manager;
	@Autowired
	private RefreshTokenRepository refreshTokenService;
	@Autowired
	private JWTHelper helper;
	@Autowired
	private PasswordEncoder encoder;
	@Autowired
	private UserRepository userRep;
	
	@PostMapping("/login")
	@Transactional
	public ResponseEntity<?> login(@Valid @RequestBody LoginDTO dto){
		Authentication auth = manager.authenticate(new UsernamePasswordAuthenticationToken(dto.getLogin(), 
																						   dto.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(auth);
		JenjetsuUser u = userRep.findByLogin(auth.getName()).orElseThrow(() -> new UsernameNotFoundException("asdfa"));
		RefreshToken token = new RefreshToken();
		token.setOwnerId(u);
		refreshTokenService.save(token);
		String accessToken = helper.generateAccessToken(u);
		String refreshToken = helper.generateRefreshToken(u, token.getId());
		return ResponseEntity.ok(new TokenDTO(u.getId(), accessToken, refreshToken));
	}
	
	@PostMapping("/singup")
	@Transactional
	public ResponseEntity<?> singup(@Valid @RequestBody SingupDTO dto){
		JenjetsuUser u = new JenjetsuUser();
		u.setLogin(dto.getLogin());
		u.setEmail(dto.getEmail());
		u.setPassword(encoder.encode(dto.getPassword()));
		userRep.save(u);
		RefreshToken token = new RefreshToken();
		token.setOwnerId(u);
		refreshTokenService.save(token);
		String accessToken = helper.generateAccessToken(u);
		String refreshToken = helper.generateRefreshToken(u, token.getId());
		return ResponseEntity.ok(new TokenDTO(u.getId(), accessToken, refreshToken));
	}
	
	@PostMapping("/logout")
	public ResponseEntity<?> logout(@Valid @RequestBody TokenDTO dto){
		String refreshToken = dto.getRefreshToken();
		if(helper.validateRefreshToken(refreshToken) && 
				refreshTokenService.existsById(helper.getTokenIdFromRefreshToken(refreshToken))) {
			refreshTokenService.deleteById(helper.getTokenIdFromRefreshToken(refreshToken));
			return ResponseEntity.ok().build();
		}
		throw new BadCredentialsException("invalid token");
	}
	
	@PostMapping("logout-all")
	public ResponseEntity<?> logoutAll(@RequestBody TokenDTO dto){
		String refreshToken = dto.getRefreshToken();
		if(helper.validateRefreshToken(refreshToken) && 
				refreshTokenService.existsById(helper.getTokenIdFromRefreshToken(refreshToken))) {
			refreshTokenService.deleteByOwnerId(helper.getUserIdFromRefreshToken(refreshToken));
			return ResponseEntity.ok().build();
		}
		throw new BadCredentialsException("invalid token");
	}
	
	@PostMapping("/refresh-token")
	@Transactional
	public ResponseEntity<?> refresh(@RequestBody TokenDTO dto){
		String refreshToken = dto.getRefreshToken();
		if(helper.validateRefreshToken(refreshToken) &&
				refreshTokenService.existsById(helper.getTokenIdFromRefreshToken(refreshToken))) {
			refreshTokenService.deleteById(helper.getTokenIdFromRefreshToken(refreshToken));
			RefreshToken token = new RefreshToken();
			JenjetsuUser u = userRep.findById(null)
					.orElseThrow(() -> new UsernameNotFoundException("bad user id"));
			token.setOwnerId(u);
			refreshTokenService.save(token);
			TokenDTO ret = new TokenDTO();
			ret.setAccessToken(helper.generateAccessToken(u));
			ret.setRefreshToken(helper.generateRefreshToken(u, token.getId()));
			ret.setUserId(u.getId());
			return ResponseEntity.ok(ret);
		}
		throw new BadCredentialsException(String.format("invalid refresh token: %s", refreshToken));
	}
	
	@PostMapping("/access-token")
	public ResponseEntity<?> updateAccessToken(@RequestBody TokenDTO dto){
		String refreshToken = dto.getRefreshToken();
		if(helper.validateRefreshToken(refreshToken) &&
				refreshTokenService.existsById(helper.getTokenIdFromRefreshToken(refreshToken))) {
			JenjetsuUser u = userRep.findById(helper.getUserIdFromRefreshToken(refreshToken))
									.orElseThrow(() -> new UsernameNotFoundException("bad user id"));
			String accessToken = helper.generateAccessToken(u);
			TokenDTO ret = new TokenDTO();
			ret.setAccessToken(accessToken);
			ret.setRefreshToken(refreshToken);
			ret.setUserId(u.getId());
			return ResponseEntity.ok(ret);
		}
		throw new BadCredentialsException(String.format("invalid refresh token: %s", refreshToken));
	}
}
