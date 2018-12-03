package registration;

public class RegistrationDetails {
    private String email;

    public RegistrationDetails(String email) {
        this.email = email;
    }

    @SuppressWarnings("WeakerAccess")
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
