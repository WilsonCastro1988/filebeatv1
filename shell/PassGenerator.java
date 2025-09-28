import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PassGenerator {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Uso: java BcryptGenerator <password>");
            System.exit(1);
        }
        String rawPassword = args[0];
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode(rawPassword));
    }
}
