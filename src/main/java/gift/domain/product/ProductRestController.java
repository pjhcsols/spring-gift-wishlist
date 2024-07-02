package gift.domain.product;

import gift.domain.product.dto.ProductRequestDto;
import gift.domain.product.dto.ProductResponseDto;
import gift.global.response.SuccessResponse;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/products")
public class ProductRestController {

    private final ProductService productService;

    @Autowired
    public ProductRestController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getProducts() {
        return SuccessResponse.ok(productService.getAllProducts(), "products");
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> addProduct(@RequestBody ProductRequestDto requestDto) {
        ProductResponseDto responseDto = productService.addProduct(requestDto);
        return SuccessResponse.created(
            responseDto,
            "created-product",
            "/api/products/{id}",
            responseDto.id());
    }

    @PutMapping("/{id}")
    public ResponseEntity<Map<String, Object>> updateProduct(@PathVariable("id") Long id,
                                                             @RequestBody ProductRequestDto requestDto) {
        productService.updateProductById(id, requestDto);
        return SuccessResponse.ok();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> deleteProduct(@PathVariable("id") Long id) {
        productService.deleteProduct(id);
        return SuccessResponse.ok();
    }
}
