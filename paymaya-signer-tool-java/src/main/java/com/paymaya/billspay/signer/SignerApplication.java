package com.paymaya.billspay.signer;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Paymaya Signer application - Java Based Example
 *
 */
public class SignerApplication {
	// this is an example payload incoming to Partner Biller API from Paymaya
    private static String SAMPLE_VALIDATE_REQUEST_PAYLOAD = "{\"id\":\"b46f3f8a-de24-4b66-9d38-02e18484be67\","
            + "\"biller\":{\"accountNumber\":\"test\","
            + "\"slug\":\"TESTSLUG\",\"fields\":{\"firstName\":\"John\",\"lastName\":\"Smith\","
            + "\"contactNumber\":\"+639384618830\"}},\"transaction\":{\"date\":\"2018-10-23T06:22:00.588Z\","
            + "\"amount\":{\"currency\":\"PHP\",\"value\":110}}}";

    // this is a Secret Key, that is shared during onboarding
    private static String SAMPLE_SECRET_KEY = "sk-testKey";

	public static final String ALGO_HMAC_SHA_256 = "HmacSHA256";

	/**
	 * The entry point of application.
	 *
	 * @param args the input arguments
	 */
	public static void main(String[] args) {
        // perform
        String signatureComputed = getSignature(
                SAMPLE_VALIDATE_REQUEST_PAYLOAD,
                SAMPLE_SECRET_KEY
        );

        /**
         Note:
         - the computed signature above will be compared against the signature attached to the request
         in the 'paymaya-signature' header.
         - if computed signature matches then the request is valid and has not been tampered with.
         - if it does not match, the request is invalid, and might have been tampered wit
         */

        // output of computed signature
        // signature: D+IKW5fHA4E4YiKAy/3nxDtsTbYVds0rAzFNNz3bSM4=
        System.out.println("Computed Paymaya Signature: " + signatureComputed);
    }

	/**
	 * Gets signature.
	 *
	 * @param payload the payload
	 * @param key the key
	 *
	 * @return the signature
	 */
	public static String getSignature(
            String payload,
            String key
    ) {
        String base64Auth = getHashedSecretKey(key);
        Charset asciiCs = StandardCharsets.US_ASCII;

        try {
            Mac sha256Hmac = Mac.getInstance(ALGO_HMAC_SHA_256);

            SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                    asciiCs.encode(base64Auth)
                            .array(),
                    ALGO_HMAC_SHA_256
            );
            sha256Hmac.init(secretKey);

            final byte[] macData = sha256Hmac.doFinal(asciiCs.encode(payload)
                                                              .array());

            return new String(Base64.encodeBase64(macData));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return "";
    }

	/**
	 * Gets hashed secret key.
	 *
	 * @param secretKey the secret key
	 *
	 * @return the hashed secret key
	 */
	public static String getHashedSecretKey(String secretKey) {
        return new String(Base64.encodeBase64(secretKey.getBytes()));
    }
}
