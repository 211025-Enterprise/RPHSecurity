package com.revature.rphSecurity.aspects;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.revature.rphSecurity.RPHSecurityService;
import com.revature.rphSecurity.annotations.EndPointSecurity;
import net.bytebuddy.implementation.bytecode.Throw;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.nio.file.AccessDeniedException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeoutException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

@Component
@Aspect
public class RPHSecurityAspect {
	@Value("${RPH.secret:secret}")
	private String secret;
	@Value("${RPH.Issuer:issuer}")
	private String Issuer;
	@Value("${RPH.TimeOut:500}")
	private int TimeOut;

	Logger logger = LoggerFactory.getLogger(RPHSecurityAspect.class);
	@Pointcut("@annotation(com.revature.rphSecurity.annotations.EndPointSecurity)")
	public void intercept(){}

	@Pointcut("execution(* javax.servlet.http.HttpServlet+.*(..))")
	public void interceptMVC(){}

	private HttpServletRequest request;

	@Before("interceptMVC()")
	private void beforeInterceptMVC(JoinPoint joinPoint){
		request = (HttpServletRequest) joinPoint.getArgs()[0];
	}

	@Around("intercept()")
	public Object beforeIntercept(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
		logger.info("Attempted Access Detected");
		Map<String,Object> map;
		try{
			Algorithm algorithm = Algorithm.HMAC256(secret);
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(Issuer).build();

			DecodedJWT jwt = verifier.verify(request.getHeader("Authorization").split(" ")[1]);
			Base64.Decoder decoder = Base64.getDecoder();
			String s = new String(decoder.decode(jwt.getPayload()));
			map = new ObjectMapper().readValue(s, HashMap.class);
			if ((Integer)map.get("exp") > Instant.now().toEpochMilli()) throw  new TimeoutException();
			MethodSignature methodSignature = (MethodSignature)proceedingJoinPoint.getSignature();
			if  (Arrays.stream(methodSignature.getMethod().getAnnotation(EndPointSecurity.class).allowedUserTypes()).noneMatch(T->T.equals(map.get("allowedUserType")))) throw new Exception();
		} catch (Exception e){
			logger.warn("Attempted Access Failed: " + e.getMessage());
			return "Not Authorized";
		}
		logger.info("Attempted Access Granted of user: "+map.get("allowedUserType"));
		return proceedingJoinPoint.proceed(proceedingJoinPoint.getArgs());
	}




}
