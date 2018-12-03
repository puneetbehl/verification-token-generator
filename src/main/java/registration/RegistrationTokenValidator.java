package registration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.*;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.text.ParseException;
import java.util.Date;

@Singleton
public class RegistrationTokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(RegistrationTokenValidator.class);

    private final RegistrationSecretSignature registrationSecretSignature;

    public RegistrationTokenValidator(@Nullable RegistrationSecretSignature registrationSecretSignature) {
        this.registrationSecretSignature = registrationSecretSignature;
    }

    private boolean validateExpirationTime(JWTClaimsSet claimSet) {
        final Date expTime = claimSet.getExpirationTime();
        if (expTime != null) {
            final Date now = new Date();
            return !expTime.before(now);
        }
        return true;
    }

    public Publisher<TokenDetails> validateToken(String token) {
        try {
            JWT jwt = JWTParser.parse(token);

            if (jwt instanceof PlainJWT) {
                return validatePlainJWT(jwt);
            } else if (jwt instanceof SignedJWT) {
                final SignedJWT signedJWT = (SignedJWT) jwt;
                return validateSignedJWT(signedJWT);
            }
            return Flowable.empty();

        } catch (final ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cannot decrypt / verify JWT: {}", e.getMessage());
            }
            return Flowable.empty();
        }
    }

    private Publisher<TokenDetails> validatePlainJWT(JWT jwt) throws ParseException {
        if (registrationSecretSignature == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT is not signed and no signature configurations -> verified");
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("A non-signed JWT cannot be accepted as signature configurations have been defined");
            }
            return Flowable.empty();
        }
        return createTokenDetails(jwt);
    }

    private Publisher<TokenDetails> validateSignedJWT(SignedJWT signedJWT) throws ParseException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("JWT is signed");
        }
        final JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
        if (registrationSecretSignature != null) {
            if (registrationSecretSignature.supports(algorithm)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using signature configuration: {}", registrationSecretSignature.toString());
                }
                try {
                    if (registrationSecretSignature.verify(signedJWT)) {
                        return createTokenDetails(signedJWT);
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("JWT verification failed: {}", signedJWT.getParsedString());
                        }
                    }
                } catch (final JOSEException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Verification fails with signature configuration: {}, passing to the next one", registrationSecretSignature);
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("{}", registrationSecretSignature.supportedAlgorithmsMessage());
                }
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("No signature algorithm found for JWT: {}", signedJWT.getParsedString());
        }
        return Flowable.empty();
    }

    private Publisher<TokenDetails> createTokenDetails(JWT jwt) throws ParseException {
        final JWTClaimsSet claimSet = jwt.getJWTClaimsSet();
        final String subject = claimSet.getSubject();

        if (subject == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT must contain a subject ('sub' claim)");
            }
            return Flowable.empty();
        }

        if (!validateExpirationTime(jwt.getJWTClaimsSet())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT expired");
            }
            return Flowable.empty();
        }

        return Flowable.just(claimSet::getClaims);
    }

}
