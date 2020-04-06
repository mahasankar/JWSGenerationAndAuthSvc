package com.sspl.jws.controller;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sspl.jws.keymgmt.PrivateKeyRegistry;
import com.sspl.jws.keymgmt.PublicKeyRegistry;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@Configuration
public class JWSAPIRequestController 
{
	private static final Logger LOGGER = LoggerFactory.getLogger(JWSAPIRequestController.class);
	
	@RequestMapping(value = "/signAPIRequest", method = {RequestMethod.POST}, consumes = {MediaType.TEXT_PLAIN_VALUE})
	public String signAPIRequest(@RequestHeader("header-key-id") String keyId,
								 @RequestBody String payloadAsStr) 
	{
		LOGGER.info("header-key-id => " + keyId);
		LOGGER.info("payload => " + payloadAsStr);
		
		String jwt = null;
		try 
		{
			PrivateKey privateKey = PrivateKeyRegistry.getPrivateKey(keyId);
	        
	        LOGGER.info(privateKey.toString());
	        
	        JsonWebSignature jws = new JsonWebSignature();
	        
	        // Create the Claims, which will be the content of the JWT along with the request payload
	        JwtClaims claims = new JwtClaims();
	        claims.setClaim("payload", payloadAsStr); 
	        
	        // Set the request pay load to sign
	        jws.setPayload(claims.toJson());
	        
	        // Sign the pay load using the private key
	        jws.setKey(privateKey);
	        
	        // Set the Key ID
	        jws.setKeyIdHeaderValue(keyId);
	        
	        // Set the signature algorithm on the JWS 
	        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

			//signature = jws.getDetachedContentCompactSerialization();
			
			jwt = jws.getCompactSerialization();
			
			LOGGER.info("Digital signature successfully done for API request.");
			
			return jwt;
		} 
		catch (Exception e) 
		{
			String response = "Error encountered while digitally signing the API request.";
			LOGGER.error(response);
			e.printStackTrace();
			return response;
		}
	}
	
	@RequestMapping(value = "/verifyAPIRequest", method = {RequestMethod.POST}, consumes = {MediaType.TEXT_PLAIN_VALUE})
	public String verifyAPIRequest(@RequestHeader("header-key-id") String keyId,
								   @RequestBody String jwt) 
	{
		LOGGER.info("header-key-id => " + keyId);
		LOGGER.info("jwt => " + jwt);
		
		try 
		{
			PublicKey publicKey = PublicKeyRegistry.getPublicKey(keyId);
	        
	        LOGGER.info(publicKey.toString());
	        
	        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
	        							.setVerificationKey(publicKey)
	        							.setJwsAlgorithmConstraints(ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256)
	        							.build();
	        
	        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
	        
	        LOGGER.info("JWS validation succeeded! " + jwtClaims);
	        
	        return "Successfully verified the digital signature on the API request.";
	    } 
		catch (Exception e) 
		{
			String response = "Error encountered while verifying the digital signature on the API request.";
			LOGGER.error(response);
			e.printStackTrace();
			return response;
		}
	}
}
