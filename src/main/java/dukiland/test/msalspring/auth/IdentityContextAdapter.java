package dukiland.test.msalspring.auth;

import java.io.IOException;

public interface IdentityContextAdapter {

    void setContext(IdentityContextData context);

    IdentityContextData getContext();

    void redirectUser(String location) throws IOException;

    String getParameter(String parameterName);

}
