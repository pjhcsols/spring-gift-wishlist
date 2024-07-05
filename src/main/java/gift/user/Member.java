package gift.user;

import jakarta.validation.constraints.Email;

public record Member(
    @Email(message = "This is not an email format")
    String email,
    String password) {

}
