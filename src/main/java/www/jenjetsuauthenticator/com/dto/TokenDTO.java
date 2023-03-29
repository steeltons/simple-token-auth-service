package www.jenjetsuauthenticator.com.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenDTO {
	private long userId;
	private String accessToken;
	private String refreshToken;
}
