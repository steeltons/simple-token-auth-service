package www.jenjetsuauthenticator.com.security;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import www.jenjetsuauthenticator.com.entity.JenjetsuUser;

@Component
@Slf4j
public class JWTHelper {
	
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
	
	private final String ISSUER = "jenjetsu";
	@Getter
	private final long accessTokenExpirationMs;
	@Getter
	private final long refreshTokenExpirtationMs;
	private Algorithm accessTokenAlgorithm;
	private Algorithm refreshTokenAlgorithm;
	private JWTVerifier accessTokenVerifier;
	private JWTVerifier refreshTokenVerifier;
	
	public JWTHelper(@Value("${accessTokenSecret}") String accessTokenSecret, 
							   @Value("${refreshTokenSecret}") String refreshTokenSecret,
							   @Value("${accessTokenExpirationMinutes}") long accessExpMs, 
							   @Value("${refreshTokenExpirationDays}") long refreshExpMs) {
		accessTokenAlgorithm = Algorithm.HMAC512(accessTokenSecret);
		refreshTokenAlgorithm = Algorithm.HMAC512(refreshTokenSecret);
		accessTokenVerifier = JWT.require(accessTokenAlgorithm)
								 .withIssuer(ISSUER)
								 .build();
		refreshTokenVerifier = JWT.require(refreshTokenAlgorithm)
								  .withIssuer(ISSUER)
								  .build();
		accessTokenExpirationMs = accessExpMs * 60 * 1000;
		refreshTokenExpirtationMs = refreshExpMs * 60 * 60 * 1000;
	}
	
	public String generateAccessToken(JenjetsuUser u) {
		LocalDateTime now = LocalDateTime.ofInstant(Instant.now(), ZoneId.of("Europe/Moscow"));
		LocalDateTime expr = LocalDateTime.ofInstant(Instant.now(), ZoneId.of("Europe/Moscow"))
										  .plusMinutes(accessTokenExpirationMs);
		return JWT.create()
				  .withIssuer(ISSUER)
				  .withSubject(u.getId().toString())
				  .withClaim("login", u.getLogin())
				  .withIssuedAt(Date.from(now.atZone(ZoneId.of("Europe/Moscow")).toInstant()))
				  .withExpiresAt(Date.from(expr.atZone(ZoneId.of("Europe/Moscow")).toInstant()))
				  .sign(accessTokenAlgorithm);
				  
	}
	
	public String generateRefreshToken(JenjetsuUser u, String tokenId) {
		LocalDateTime now = LocalDateTime.ofInstant(Instant.now(), ZoneId.of("Europe/Moscow"));
		LocalDateTime expr = LocalDateTime.ofInstant(Instant.now(), ZoneId.of("Europe/Moscow"))
										  .plusMinutes(accessTokenExpirationMs);
		return JWT.create()
				  .withIssuer(ISSUER)
				  .withSubject(u.getId().toString())
				  .withClaim("tokenId", tokenId)
				  .withClaim("login", u.getLogin())
				  .withIssuedAt(Date.from(now.atZone(ZoneId.of("Europe/Moscow")).toInstant()))
				  .withExpiresAt(Date.from(expr.atZone(ZoneId.of("Europe/Moscow")).toInstant()))
				  .sign(refreshTokenAlgorithm);
				  
	}
	
	public boolean validateAccessToken(String token) {
		return decodeAccessToken(token).isPresent();
	}
	
	public boolean validateRefreshToken(String token) {
		return decodeRefreshToken(token).isPresent();
	}
	
	public long getUserIdFromAccessToken(String token) {
		return Long.parseLong(decodeAccessToken(token).get().getSubject());
	}
	
	public long getUserIdFromRefreshToken(String token) {
		return Long.parseLong(decodeRefreshToken(token).get().getSubject());
	}
	
	public String getTokenIdFromRefreshToken(String token) {
		return decodeRefreshToken(token).get().getClaim("tokenId").asString();
	}
	
	private Optional<DecodedJWT> decodeAccessToken(String token){
		try {
			return Optional.of(accessTokenVerifier.verify(token));
		} catch(JWTVerificationException e) {
			log.error("Invalid access token", e);
		}
		return Optional.empty();
	}
	
	private Optional<DecodedJWT> decodeRefreshToken(String token){
		try {
			return Optional.of(refreshTokenVerifier.verify(token));
		} catch(JWTVerificationException e) {
			log.error("Invalid refresh token", e);
		}
		return Optional.empty();
	}
	
}
