package dukiland.test.msalspring.auth;

import com.microsoft.aad.msal4j.*;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

@Slf4j
public class AuthHelper {

    public static boolean singIn(IdentityContextAdapter contextAdapter) throws IOException, AuthException {
        return authorize(contextAdapter);
    }

    public static boolean authorize(IdentityContextAdapter contextAdapter) throws IOException, AuthException {
        boolean result = true;
        final IdentityContextData context = contextAdapter.getContext();

        if (context.getAccount() != null) {
            log.info("세션에서 계정을 찾았습니다. 자동으로 토큰을 획득합니다.");
            acquireTokenSilently(contextAdapter);
        } else {
            log.info("세션에서 계정을 찾지 못했습니다. 토큰 획득을 시도합니다.");
            redirectToAuthorizationEndpoint(contextAdapter);
            result = false;
        }
        return result;
    }

    public static void acquireTokenSilently(IdentityContextAdapter contextAdapter) throws AuthException {
        final IdentityContextData context = contextAdapter.getContext();

        if (context.getAccount() == null) {
            String msg = "자동으로 토큰을 획득하려면 세션에 계정이 있어야합니다.";
            log.warn(msg);
            throw new AuthException(msg);
        }
        final SilentParameters parameters = SilentParameters.builder(Collections.singleton(Config.SCOPES), context.getAccount()).build();

        try {
            final ConfidentialClientApplication clientApplication = getConfidentialClientInstance();
            clientApplication.tokenCache().deserialize(context.getTokenCache());
            final IAuthenticationResult result = clientApplication.acquireTokenSilently(parameters).get();
            if (result != null) {
                context.setAuthResult(result, clientApplication.tokenCache().serialize());
            } else {
                String msg = "자동인증에서 NULL이 반환되어 실패하였습니다.";
                log.error(msg);
                throw new AuthException(msg);
            }
        } catch (final Exception ex) {
            String msg = "자동인증에 실패하였습니다.";
            log.error(msg);
            throw new AuthException(msg);
        }
    }

    public static ConfidentialClientApplication getConfidentialClientInstance() throws MalformedURLException {
        ConfidentialClientApplication confidentialClientApplication = null;
        try {
            final IClientSecret secret = ClientCredentialFactory.createFromSecret(Config.SECRET);
            confidentialClientApplication = ConfidentialClientApplication.builder(Config.CLIENT_ID, secret).authority(Config.AUTHORITY).build();
        } catch (final Exception ex) {
            log.error("ConfidentialClientApplication을 만들지 못했습니다.", ex);
            throw ex;
        }
        return confidentialClientApplication;
    }

    private static void redirectToAuthorizationEndpoint(IdentityContextAdapter contextAdapter) throws IOException {
        final IdentityContextData context = contextAdapter.getContext();

        final String state = UUID.randomUUID().toString();
        final String nonce = UUID.randomUUID().toString();

        context.setStateAndNonce(state, nonce);
        contextAdapter.setContext(context);

        final ConfidentialClientApplication client = getConfidentialClientInstance();
        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                .builder(Config.REDIRECT_URI, Collections.singleton(Config.SCOPES)).responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT).state(state).nonce(nonce).build();

        final String authorizeUrl = client.getAuthorizationRequestUrl(parameters).toString();
        contextAdapter.redirectUser(authorizeUrl);
    }

    public static void processAADCallback(IdentityContextAdapter contextAdapter) throws AuthException {
        final IdentityContextData context = contextAdapter.getContext();

        try {
            validateState(contextAdapter);
            processErrorCodes(contextAdapter);

            final String authCode = contextAdapter.getParameter("code");
            if (authCode == null) {
                throw new AuthException("요청정보에 인증 코드가 없습니다.");
            }

            final AuthorizationCodeParameters authParams = AuthorizationCodeParameters.builder(authCode, new URI(Config.REDIRECT_URI)).scopes(Collections.singleton(Config.SCOPES)).build();
            final ConfidentialClientApplication client = AuthHelper.getConfidentialClientInstance();
            final IAuthenticationResult result = client.acquireToken(authParams).get();

            context.setIdTokenClaims(result.idToken());

            validateNonce(context);

            context.setAuthResult(result, client.tokenCache().serialize());
        } catch (final Exception ex) {
            contextAdapter.setContext(null);
            String message = "인증정보를 토큰으로 교환할 수 없습니다.";
            log.error(message);
            throw new AuthException(message);
        }
    }

    private static void validateState(IdentityContextAdapter contextAdapter) throws AuthException {
        final String requestState = contextAdapter.getParameter("state");
        final IdentityContextData context = contextAdapter.getContext();
        final String sessionState = context.getState();
        final Date now = new Date();

        if (sessionState == null || requestState == null || !sessionState.equals(requestState)
                || context.getStateDate().before(new Date(now.getTime() - (Config.STATE_TTL * 1000)))) {
            throw new AuthException("토큰 상태가 만료되었거나 비어있습니다.");
        }

        context.setState(null);
    }

    private static void processErrorCodes(IdentityContextAdapter contextAdapter) throws AuthException {
        final String error = contextAdapter.getParameter("error");
        final String errorDescription = contextAdapter.getParameter("error_description");
        if (error != null || errorDescription != null) {
            throw new AuthException(String.format("Azure Active Directory로 부터 에러를 받았습니다. Error: %s %nErrorDescription: %s", error, errorDescription));
        }
    }

    private static void validateNonce(IdentityContextData context) throws AuthException {
        final String nonceClaim = (String) context.getIdTokenClaims().get("nonce");
        final String sessionNonce = context.getNonce();
        if (sessionNonce == null || !sessionNonce.equals(nonceClaim)) {
            throw new AuthException("토큰 유효성 검사에 실패하였습니다.");
        }
        context.setNonce(null);
    }

    public static void signOut(IdentityContextAdapter contextAdapter) throws IOException {
        redirectToSignOutEndpoint(contextAdapter);
    }

    public static void redirectToSignOutEndpoint(IdentityContextAdapter contextAdapter) throws IOException {
        contextAdapter.setContext(null);
        final String redirect = String.format("%s%s%s%s", Config.AUTHORITY, Config.SIGN_OUT_ENDPOINT,
                Config.POST_SIGN_OUT_FRAGMENT, URLEncoder.encode(Config.HOME_PAGE, "UTF-8"));
        contextAdapter.redirectUser(redirect);
    }

}
