package registration

import io.micronaut.context.ApplicationContext
import io.micronaut.test.annotation.MicronautTest
import io.reactivex.Flowable
import registration.RegistrationDetails
import registration.RegistrationTokenGenerator
import registration.RegistrationTokenValidator
import spock.lang.Specification

import javax.inject.Inject

@MicronautTest
class RegistrationTokenValidatorSpec extends Specification {

    @Inject
    ApplicationContext applicationContext

    void "test validate plain jwt token"() {
        when:
        RegistrationDetails registrationDetails = new RegistrationDetails("test@example.com")
        RegistrationTokenGenerator tokenGenerator = applicationContext.getBean(RegistrationTokenGenerator)
        RegistrationTokenValidator tokenValidator = applicationContext.getBean(RegistrationTokenValidator)
        String token = tokenGenerator.generateToken(registrationDetails, 60).get()

        then:
        TokenDetails details = Flowable.fromPublisher(tokenValidator.validateToken(token)).blockingFirst()
        details.getAttributes().get("email") == "test@example.com"
    }

    void "test validate invalid plain jwt token"() {
        when:
        RegistrationTokenValidator tokenValidator = applicationContext.getBean(RegistrationTokenValidator)

        then:
        Flowable.fromPublisher(tokenValidator.validateToken("someinvalidtoken")).isEmpty()
    }

    void "test validate signed jwt token"() {

        setup:
        ApplicationContext applicationContext1 = ApplicationContext.run(["micronaut.registration.token.jwt.signature.secret": "VkYp3s6v9y/B?E(H+MbQeThWmZq4t7w!"])

        when:
        RegistrationDetails registrationDetails = new RegistrationDetails("test@example.com")
        RegistrationTokenGenerator tokenGenerator = applicationContext1.getBean(RegistrationTokenGenerator)
        RegistrationTokenValidator tokenValidator = applicationContext1.getBean(RegistrationTokenValidator)
        String token = tokenGenerator.generateToken(registrationDetails, 60).get()

        then:
        TokenDetails tokenDetails = Flowable.fromPublisher(tokenValidator.validateToken(token)).blockingFirst()
        tokenDetails.attributes.get("email") == "test@example.com"

        cleanup:
        applicationContext1.close()
    }

}
