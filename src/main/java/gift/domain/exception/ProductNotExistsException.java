package gift.domain.exception;

public class ProductNotExistsException extends RuntimeException {
    public ProductNotExistsException() {
        super("Product does not exist");
    }
}