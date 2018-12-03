package registration;

import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.reactivex.Flowable;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.Optional;

@Controller("/token")
public class TokenController implements RegistrationTokenOperations {

    private final RegistrationTokenGenerator tokenGenerator;
    private final RegistrationTokenValidator tokenValidator;

    @SuppressWarnings("WeakerAccess")
    @Value("${micronaut.registration.token.jwt.expirationInSeconds:3600}")
    protected Integer tokenExpirationInSeconds;

    public TokenController(RegistrationTokenGenerator tokenGenerator, RegistrationTokenValidator tokenValidator) {
        this.tokenGenerator = tokenGenerator;
        this.tokenValidator = tokenValidator;
    }

    @Override
    @Get(value = "/generate/{?registrationDetails*}")
    public HttpResponse<Optional<String>> generate(@Valid RegistrationDetails registrationDetails) {
        return HttpResponse.ok(tokenGenerator.generateToken(registrationDetails, tokenExpirationInSeconds));
    }

    @Override
    @Post(value = "/validate")
    public Flowable<HttpResponse<? extends TokenDetails>> validate(@NotEmpty String token) {
        return Flowable.fromPublisher(tokenValidator.validateToken(token))
                .map(HttpResponse::ok);
    }
}
