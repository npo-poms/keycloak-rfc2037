package nl.vpro.keycloak.credential.hash;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Objects;

import org.keycloak.common.util.Base64;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class RFC2037SSHAProvider implements PasswordHashProvider {

    private final String providerId;

    public RFC2037SSHAProvider(String providerId) {
        this.providerId = providerId;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return this.providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        byte[] salt = getSalt();
        String encodedPassword = encodedCredential(rawPassword, salt);
        return PasswordCredentialModel.createFromValues(providerId, salt, 0, encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        byte[] salt = credential.getPasswordSecretData().getSalt();
        return Objects.equals(encodedCredential(rawPassword, salt), credential.getPasswordSecretData().getValue());
    }

    private String encodedCredential(String rawPassword, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(rawPassword.getBytes(StandardCharsets.UTF_8));
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest();
            return Base64.encodeBytes(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not found", e);
        }
    }

    private byte[] getSalt() {
        byte[] buffer = new byte[8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }

    @Override
    public void close() {
        // nothing to do
    }
}
