package www.jenjetsuauthenticator.com.dto;

import javax.validation.constraints.NotBlank;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginDTO {
	@NotBlank
	private String login;
	@NotBlank
	private String password;
}
