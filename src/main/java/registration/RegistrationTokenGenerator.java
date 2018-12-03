package registration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import io.micronaut.context.env.Environment;
import io.micronaut.runtime.ApplicationConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

@Singleton
public class RegistrationTokenGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(RegistrationTokenValidator.class);

    private final ApplicationConfiguration applicationConfiguration;
    private final RegistrationSecretSignature registrationSecretSignature;

    public RegistrationTokenGenerator(ApplicationConfiguration applicationConfiguration, @Nullable RegistrationSecretSignature registrationSecretSignature) {
        this.applicationConfiguration = applicationConfiguration;
        this.registrationSecretSignature = registrationSecretSignature;
    }

    public Optional<String> generateToken(RegistrationDetails registrationDetails, @Nullable Integer expirationInSeconds) {
        Map<String, Object> claims = generateClaims(registrationDetails, expirationInSeconds);
        return generateToken(claims);
    }

    @SuppressWarnings("WeakerAccess")
    public Map<String, Object> generateClaims(RegistrationDetails registrationDetails, Integer expirationInSeconds) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        builder.subject(registrationDetails.getEmail())
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plus(expirationInSeconds, ChronoUnit.SECONDS)))
                .issuer(applicationConfiguration != null ? applicationConfiguration.getName().orElse(Environment.MICRONAUT) : Environment.MICRONAUT)
                .notBeforeTime(new Date())
                .claim("email", registrationDetails.getEmail());

        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated claim set: {}", builder.build().toJSONObject().toString());
        }
        return builder.build().getClaims();
    }

    @SuppressWarnings("WeakerAccess")
    public Optional<String> generateToken(Map<String, Object> claims) {
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        for (final Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        JWT jwt;
        if (registrationSecretSignature == null) {
            jwt = new PlainJWT(builder.build());
        } else {
            try {
                jwt = registrationSecretSignature.sign(builder.build());
            } catch (JOSEException e) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("JOSEException while generating token {}", e.getMessage());
                }
                return Optional.empty();
            }
        }
        return Optional.of(jwt.serialize());
    }
}
