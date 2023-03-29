package www.jenjetsuauthenticator.com.entity;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SingupDTO {

	@NotBlank
	private String login;
	@NotBlank
	private String password;
	@NotBlank
	@Email
	private String email;
}
