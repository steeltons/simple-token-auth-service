package www.jenjetsuauthenticator.com.security;

import static java.util.Collections.emptyList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import www.jenjetsuauthenticator.com.entity.JenjetsuUser;
import www.jenjetsuauthenticator.com.repositiry.UserRepository;;

@Service
public class UserDetailsServiceImpl implements UserDetailsService{

	private final UserRepository userRep;
	
	public UserDetailsServiceImpl(UserRepository userRep) {
		this.userRep = userRep;
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		JenjetsuUser u = userRep.findByLogin(username).orElseThrow(() -> new UsernameNotFoundException(username));
		return new User(u.getLogin(), u.getPassword(), emptyList());
	}

	public JenjetsuUser findById(Long id) {
		return userRep.findById(id)
					  .orElseThrow(() -> new UsernameNotFoundException("user id not found"));
	}
}
