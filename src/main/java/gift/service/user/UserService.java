package gift.service.user;


import gift.domain.user.User;
import gift.exception.user.InvalidCredentialsException;
import gift.exception.user.UserAlreadyExistsException;
import gift.exception.user.UserNotFoundException;
import gift.repository.user.UserRepository;
import gift.util.JwtResponse;
import gift.util.JwtTokenUtil;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final JwtTokenUtil jwtTokenUtil;

    @Autowired
    public UserService(UserRepository userRepository, JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    public String login(String email, String password) throws UserNotFoundException, InvalidCredentialsException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!BCrypt.checkpw(password, user.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        return jwtTokenUtil.generateAccessToken(email);
    }


    public String generateRefreshToken(String email) {
        return jwtTokenUtil.generateRefreshToken(email);
    }

    public void blacklistToken(String token) {
        jwtTokenUtil.blacklistToken(token);
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public void registerUser(String email, String password) throws UserAlreadyExistsException {
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("User already exists");
        }
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
        User newUser = new User(email, hashedPassword);
        userRepository.save(newUser);
    }
}


/*
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    public String login(String email, String password) throws UserNotFoundException, InvalidCredentialsException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        return jwtTokenUtil.generateAccessToken(email);
    }

    public String generateRefreshToken(String email) {
        //System.out.println("token: " + jwtTokenUtil.generateRefreshToken(email));
        return jwtTokenUtil.generateRefreshToken(email);
    }

    public void blacklistToken(String token) {
        jwtTokenUtil.blacklistToken(token);
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public void registerUser(String email, String password) throws UserAlreadyExistsException {
        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("User already exists");
        }
        String encodedPassword = passwordEncoder.encode(password);
        User newUser = new User(email, encodedPassword); // ID 없이 생성
        userRepository.save(newUser);
    }
}

 */
