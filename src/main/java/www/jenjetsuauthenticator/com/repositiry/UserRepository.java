package www.jenjetsuauthenticator.com.repositiry;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import www.jenjetsuauthenticator.com.entity.JenjetsuUser;

@Repository
public interface UserRepository extends JpaRepository<JenjetsuUser, Long>{

	public Optional<JenjetsuUser> findByLogin(String login);
	
}
