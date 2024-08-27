package nl.vpro.keycloak.credential.hash;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class RFC2037SSHAProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "rfc2037-ssha";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new RFC2037SSHAProvider(ID);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }
}
