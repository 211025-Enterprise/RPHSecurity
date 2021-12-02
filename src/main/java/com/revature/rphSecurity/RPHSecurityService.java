package com.revature.rphSecurity;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.revature.rphSecurity.aspects.RPHSecurityAspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class RPHSecurityService {
	Logger logger = LoggerFactory.getLogger(RPHSecurityService.class);
	@Value("${RPH.secret:secret}")
	private String secret;
	@Value("${RPH.Issuer:issuer}")
	private String Issuer;
	@Value("${RPH.TimeOut:500}")
	private int TimeOut;


	public String generateToken(String userType, Map<String,String> Payload){
		Algorithm algorithm = Algorithm.HMAC256(secret);
		JWTCreator.Builder token = JWT.create().withExpiresAt(Date.from(Instant.now().plusSeconds(TimeOut))).withIssuer(Issuer);
		Payload.keySet().forEach(x->token.withClaim(x,Payload.get(x)));
		logger.info("Generated Access Token of Type: "+userType);
		return token.withClaim("allowedUserType",userType).sign(algorithm);

	}
	public String generateToken(String userType){
		Algorithm algorithm = Algorithm.HMAC256(secret);
		JWTCreator.Builder token = JWT.create().withExpiresAt(Date.from(Instant.now().plusSeconds(TimeOut))).withIssuer(Issuer);
		logger.info("Generated Access Token of Type: "+userType);
		return token.withClaim("allowedUserType",userType).sign(algorithm);

	}
}
