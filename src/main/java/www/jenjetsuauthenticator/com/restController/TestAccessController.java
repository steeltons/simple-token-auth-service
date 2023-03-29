package www.jenjetsuauthenticator.com.restController;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
public class TestAccessController {
	
	@GetMapping
	public ResponseEntity<?> test(HttpServletRequest req){
		String remoteAddr = req.getRemoteAddr();
		String shlak = UUID.randomUUID().toString();
		Map<String, Object> json = new HashMap<>();
		json.put("ip", remoteAddr);
		json.put("uuid", shlak);
		return ResponseEntity.ok(json);
	}
}
