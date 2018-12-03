package registration;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Requires;

import javax.inject.Singleton;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

@Singleton
@Requires(property = RegistrationSecretSignature.PREFIX)
public class RegistrationSecretSignature {

    static final String PREFIX = RegistrationConfigurationProperties.PREFIX + ".signature.secret";

    private byte[] secret;
    private JWSAlgorithm algorithm;

    public RegistrationSecretSignature(RegistrationConfigurationProperties registrationConfigurationProperties) {
        RegistrationConfigurationProperties.SecretConfiguration config = registrationConfigurationProperties.getSecretConfiguration();
        if (config.getSecret() != null) {
            this.secret = config.isBase64() ? Base64.getDecoder().decode(config.getSecret()) : config.getSecret().getBytes(UTF_8);
        }
        this.algorithm = config.getJwsAlgorithm();
    }

    /**
     * @return message explaining the supported algorithms
     */
    @SuppressWarnings("WeakerAccess")
    public String supportedAlgorithmsMessage() {
        return "Only the HS256, HS384 and HS512 algorithms are supported for HMac signature";
    }

    @SuppressWarnings("WeakerAccess")
    public boolean supports(final JWSAlgorithm algorithm) {
        return algorithm != null && MACVerifier.SUPPORTED_ALGORITHMS.contains(algorithm);
    }

    @SuppressWarnings("WeakerAccess")
    public SignedJWT sign(final JWTClaimsSet claims) throws JOSEException {
        final JWSSigner signer = new MACSigner(this.secret);
        final SignedJWT signedJWT = new SignedJWT(new JWSHeader(algorithm), claims);
        signedJWT.sign(signer);
        return signedJWT;
    }

    @SuppressWarnings("WeakerAccess")
    public boolean verify(final SignedJWT jwt) throws JOSEException {
        final JWSVerifier verifier = new MACVerifier(this.secret);
        return jwt.verify(verifier);
    }

    public String getSecret() {
        return new String(secret, UTF_8);
    }

    public void setSecret(final String secret) {
        this.secret = secret.getBytes(UTF_8);
    }

    public JWSAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(JWSAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return "RegistrationSecretSignature{" +
                "secret=" + Arrays.toString(secret) +
                ", algorithm=" + algorithm +
                '}';
    }
}
