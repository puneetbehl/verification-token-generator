package registration;

import com.nimbusds.jose.JWSAlgorithm;
import io.micronaut.context.annotation.ConfigurationBuilder;
import io.micronaut.context.annotation.ConfigurationProperties;

@ConfigurationProperties(RegistrationConfigurationProperties.PREFIX)
public class RegistrationConfigurationProperties {

    static final String PREFIX = "micronaut.registration.token.jwt";

    @SuppressWarnings("WeakerAccess")
    @ConfigurationBuilder(configurationPrefix = "signature")
    protected SecretConfiguration secretConfiguration = SecretConfiguration.builder();

    public SecretConfiguration getSecretConfiguration() {
        return secretConfiguration;
    }

    static class SecretConfiguration {

        private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;
        private String secret;
        private boolean base64 = false;

        @SuppressWarnings("WeakerAccess")
        public static SecretConfiguration builder() {
            return new SecretConfiguration();
        }

        @SuppressWarnings("WeakerAccess")
        public JWSAlgorithm getJwsAlgorithm() {
            return jwsAlgorithm;
        }

        public SecretConfiguration setJwsAlgorithm(JWSAlgorithm jwsAlgorithm) {
            this.jwsAlgorithm = jwsAlgorithm;
            return this;
        }

        public String getSecret() {
            return secret;
        }

        public SecretConfiguration setSecret(String secret) {
            this.secret = secret;
            return this;
        }

        @SuppressWarnings("WeakerAccess")
        public boolean isBase64() {
            return base64;
        }

        public SecretConfiguration setBase64(boolean base64) {
            this.base64 = base64;
            return this;
        }
    }

}