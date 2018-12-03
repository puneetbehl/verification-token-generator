package registration

import io.micronaut.context.ApplicationContext
import io.micronaut.test.annotation.MicronautTest
import registration.RegistrationConfigurationProperties
import registration.RegistrationDetails
import registration.RegistrationSecretSignature
import registration.RegistrationTokenGenerator
import spock.lang.Specification

import javax.inject.Inject

@MicronautTest
class RegistrationTokenGeneratorSpec extends Specification {

    @Inject ApplicationContext applicationContext

    void "test generateToken should generate a token when no secret key"() {

        when:
        RegistrationDetails registrationDetails = new RegistrationDetails("test@example.com")
        RegistrationTokenGenerator tokenGenerator = applicationContext.getBean(RegistrationTokenGenerator)

        then:
        tokenGenerator.generateToken(registrationDetails, 60)
        !applicationContext.containsBean(RegistrationSecretSignature)
    }

    void "test generateToken should generate a token when secret key is present"() {

        when:
        ApplicationContext applicationContext1 = ApplicationContext.run(["micronaut.registration.token.jwt.signature.secret":"SOMESUPERSECUREATLEAST256BITSECRETKEY"])
        RegistrationDetails registrationDetails = new RegistrationDetails("test@example.com")
        RegistrationTokenGenerator tokenGenerator = applicationContext1.getBean(RegistrationTokenGenerator)

        then:
        tokenGenerator.generateToken(registrationDetails, 60)
        applicationContext1.getBean(RegistrationConfigurationProperties).getSecretConfiguration().secret
        applicationContext1.containsBean(RegistrationSecretSignature)

        cleanup:
        applicationContext1.close()

    }

}
