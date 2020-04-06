package com.sspl.jws.keymgmt;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;

public class PublicKeyRegistry 
{
	private static final String keyIdFIPOne = "b26435f3-5ffb-435f-9f5f-86e45451500f";
	
	private static final String rsaJsonWebKeySetAsStrFIPOne = "{\r\n" + 
			"    \"keys\": [\r\n" + 
			"        {\r\n" + 
			"            \"p\": \"un5W7fUxR8FcYLNxR2UEsiaRosKMcWLeg4k6DFMY0IGndm3oXYw5ZVobxsMuko2cIeabkiNjhZu58LbSPTKU_epmC2w_-M7hQhsZH7dujEl_WC29OxlM4xAa5fjY37wcBpSqu5ijnicwo4UJgK4rJgACJG-jLZckDdcoeiXyZ18\",\r\n" + 
			"            \"kty\": \"RSA\",\r\n" + 
			"            \"q\": \"r-_2LQ3GZ-utSezZ7NPbAENFwgPeltdLAlQnwUIHfT1XM_vd2oAfRtjtOWGZjDna_uEoG0_1B3i3cGSu8kCAqJ-QbJXyAoBpmd5c0Kk-VK9__T8_XAEO6_Fs_AEbzaliL6ilZ-RgmIs5oWjThaXhmwOYW8_aHwV8TrS_ewwXFlc\",\r\n" + 
			"            \"d\": \"dE853ucZe4fZpSmDglfWO-_GIWHlF1jYjMZZSFrqKAzAGehAYzQUfWwgVgCRlxT5xj3pWe5wdFQ-VP4OC_x5gUu6_Kzyrg6XT-89ERDLLMbqzqZ8bVmCKDcSmtLrRZmD5JJ_b0l0nA8_1A1Jp5Rzqputw1jUK6bbE2G9A1sYEIKyxyzwo-_fQR3vUQAMnueoUQz8Re-rK_1jpAoqh5J_xI3Knwxbk312g9rLir5pUwGPxEjQ4cuPuyYGoIp3D_mamRVOhrfzd7F2LbUiz5TgPe8IJQeyaPGqz-ybTQNqsmNgVIFqtTCpzWzneKuKI-h2k0MjRugvOPokAqbXcRwr1Q\",\r\n" + 
			"            \"e\": \"AQAB\",\r\n" + 
			"            \"use\": \"sig\",\r\n" + 
			"            \"kid\": \"b26435f3-5ffb-435f-9f5f-86e45451500f\",\r\n" + 
			"            \"qi\": \"EBRk7UIbbxIhRxvk2VV0eC71nUhfYAQyZuCVzJeioMhNF9BJ69sjF5NZDDCElF5jynOpxSMQe_ZSpifnpPSO2pzMA4oelNVhSaIrQtWIztuaRbQZK9agVJywB0_r3b4_J_0isvvraIRv9PcEKAEjxtLX8BzM2axFFd5JRj_0g8k\",\r\n" + 
			"            \"dp\": \"eRtYWlky8nUYB1ggRQvN297-DmMmju90rpir0JsZ7zVzSY4gKrfIAhBdH1ta4CMD9GPsPR-sHnS9cBtZNhKl_Kp-MAbRGENItwQf8Z_OM137S4kQbNOGQaIQxa0vMUPYM1HR-dcq0aaDiHz5ac4xCRFSUtUIc6_F4xMJHyGLZCM\",\r\n" + 
			"            \"alg\": \"RS256\",\r\n" + 
			"            \"dq\": \"cSauN9mlIc7UGzhGC-dQ8QFTCu18KZz7M9s12jgCIwzhWaCB1XYTJ3h6US4xF5tZ-hSKu84Xs59yssk-LrVHSaudsghZpjw6LmhxXw2J9eMNOK2FrUFM_He_9O8tl355lFctUfzyFwlrniCR8WF3EEAmq92o1cysXt4mTBfBfW8\",\r\n" + 
			"            \"n\": \"gCsstgyLflZ2-K7eK6c1tLkv-ECGrwlwc-f5AQMsso_mM6nwBy6PZ92FJp6Mm8Oe2m756JL7dBcilUoY7oNe0EyAFe9xNSuHR2r7wLcLZGBd5VxiCbpTXiydd0DfhmS0jkyKzRhFwZfXAE1DmM4T6JBJnpnUyzORAX9Fp8jZPI0eYzHGjqmviKlVkK2_vi4mtvuwvFzS0w0J4oVQKFosrM5161-RirnVUSr11AMqPU3cLeP5h818Ac7KLYPTm1wvpeKvCX5OG-wqIsWn4EwdC4m22nzOIlXMa-nSyd-ixJMqMwqeM_H_QXSxuiqsHN56iAvxgwdU1p9FvZIKd8xLSQ\"\r\n" + 
			"        }\r\n" + 
			"    ]\r\n" + 
			"}";
	
	private static Map<String, String> publicKeyRegistryMap = new HashMap<String, String>();
	
	static
	{
		publicKeyRegistryMap.put(keyIdFIPOne, rsaJsonWebKeySetAsStrFIPOne);
	}
	
	public static PublicKey getPublicKey(String keyId) throws Exception
	{
		String rsaJsonWebKeySetAsStr = publicKeyRegistryMap.get(keyId);
		
		JsonWebKeySet rsaJsonWebKeySet = new JsonWebKeySet(rsaJsonWebKeySetAsStr);
		
		RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) rsaJsonWebKeySet.getJsonWebKeys().get(0);
		
		return rsaJsonWebKey.getPublicKey();
	}
}
