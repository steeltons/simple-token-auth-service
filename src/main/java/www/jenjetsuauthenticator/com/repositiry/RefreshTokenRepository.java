package www.jenjetsuauthenticator.com.repositiry;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import www.jenjetsuauthenticator.com.entity.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String>{

	public void deleteByOwnerId(Long id);
}
