package registration;

import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.reactivex.Flowable;
import io.reactivex.Single;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;

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
    @Get(value = "/generate{?registrationDetails*}", produces = MediaType.TEXT_PLAIN)
    public Single<HttpResponse<String>> generate(@Valid RegistrationDetails registrationDetails) {
        return Single.just(tokenGenerator.generateToken(registrationDetails, tokenExpirationInSeconds))
                .map(token -> {
                    if (token.isPresent()) {
                        return HttpResponse.ok(token.get());
                    }
                    return HttpResponse.noContent();
                });
    }

    @Override
    @Post(value = "/validate")
    public Flowable<HttpResponse<? extends TokenDetails>> validate(@NotEmpty String token) {
        return Flowable.fromPublisher(tokenValidator.validateToken(token))
                .map(HttpResponse::ok);
    }
}
