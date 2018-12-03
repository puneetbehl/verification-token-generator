package registration;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.validation.Validated;
import org.reactivestreams.Publisher;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import java.util.Optional;

@Validated
public interface RegistrationTokenOperations {

    @Get(value = "/generate/{?registrationDetails*}")
    HttpResponse<Optional<String>> generate(@Valid RegistrationDetails registrationDetails);

    @Post(value = "/validate")
    Publisher<HttpResponse<? extends TokenDetails>> validate(@NotEmpty String token);
}
