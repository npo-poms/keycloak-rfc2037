package nl.vpro.keycloak.credential.hash;


import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Base64;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class RFC2037SSHAProviderTest {

    @Test
    void test() {
        RFC2037SSHAProvider provider = new RFC2037SSHAProvider("id");

        PasswordCredentialModel testwachtwoord = provider.encodedCredential("testwachtwoord", 0);
        boolean result = provider.verify("testwachtwoord", testwachtwoord);
        assertTrue(result);
    }

//    @Test
    void testLDAP() throws IOException {
        RFC2037SSHAProvider provider = new RFC2037SSHAProvider("id");

        String pass = "Na3JHgvmvRmjSI+9K1lzuyfJOp2ai6/Ay081lw==";
        String password = "xxxxxx";
        byte[] decoded = Base64.decode(pass);
        byte[] p = new byte[20];
        byte[] s = new byte[8];
        System.arraycopy(decoded, 0, p, 0, 20);
        System.arraycopy(decoded, 20, s, 0, 8);
        String encoded = Base64.encodeBytes(p);

        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues("id", s, 0, encoded);
        boolean result = provider.verify(password, passwordCredentialModel);
        assertTrue(result);
    }
}
