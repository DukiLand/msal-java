package dukiland.test.msalspring.auth;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.Properties;

@Slf4j
public class Config {

    private static Properties properties = instantiateProperties();

    public static final String SCOPES = Config.getProperty("aad.scopes");

    public static final String SECRET = Config.getProperty("aad.secret");

    public static final String CLIENT_ID = Config.getProperty("aad.clientId");

    public static final String AUTHORITY = Config.getProperty("aad.authority");

    public static final String HOME_PAGE = Config.getProperty("app.homePage");

    public static final String REDIRECT_ENDPOINT = Config.getProperty("app.redirectEndpoint");

    public static final String REDIRECT_URI = String.format("%s%s", HOME_PAGE, REDIRECT_ENDPOINT);

    public static final String SESSION_PARAM = Config.getProperty("app.sessionParam");

    public static final Long STATE_TTL = Long.parseLong(Config.getProperty("app.stateTTL"));

    public static final String SIGN_OUT_ENDPOINT = Config.getProperty("aad.signOutEndpoint");

    public static final String POST_SIGN_OUT_FRAGMENT = Config.getProperty("aad.postSignOutFragment");


    private static Properties instantiateProperties() {
        final Properties properties = new Properties();
        try {
            properties.load(Config.class.getClassLoader().getResourceAsStream("authentication.properties"));
        } catch (IOException ex) {
            log.error("인증설정 정보를 찾을 수 없습니다.");
            System.exit(1);
            return null;
        }
        return properties;
    }

    public static String getProperty(final String key) {
        String prop = null;
        if (properties != null) {
            prop = Config.properties.getProperty(key);
            if (prop != null) {
                return prop;
            } else {
                return "";
            }
        } else {
            log.error("인증설정 정보를 찾을 수 없습니다.");
            System.exit(1);
            return null;
        }
    }

}
