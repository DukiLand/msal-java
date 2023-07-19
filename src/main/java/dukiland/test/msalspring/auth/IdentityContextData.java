package dukiland.test.msalspring.auth;

import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;

import java.io.Serializable;
import java.text.ParseException;
import java.util.*;

public class IdentityContextData implements Serializable {

    private static final long serialVersionUID = 2L;

    private IAccount account = null;

    private String tokenCache = null;

    private String idToken = null;

    private String accessToken = null;

    private boolean hasChanged = false;

    private Map<String, Object> idTokenClaims = new HashMap<>();

    private List<String> groups = new ArrayList<>();

    private boolean groupsOverage = false;

    private List<String> roles = new ArrayList<>();

    private boolean authenticated = false;

    private String username = null;

    private String nonce = null;

    private String state = null;

    private Date stateDate = null;


    public IAccount getAccount() {
        return this.account;
    }

    public void setAccount(IAccount account) {
        this.account = account;
    }

    public String getTokenCache() {
        return this.tokenCache;
    }

    public void setAuthResult(IAuthenticationResult authResult, String serializedTokenCache) throws ParseException {
        this.setAccount(authResult.account());
        this.idToken = authResult.idToken();
        this.setAccessToken(authResult.accessToken());
        this.tokenCache = serializedTokenCache;
        this.setIdTokenClaims(this.idToken);
        this.username = (String)this.idTokenClaims.get("name");
        this.authenticated = true;

        this.setHasChanged(true);
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        this.setHasChanged(true);
    }

    public void setHasChanged(boolean hasChanged) {
        this.hasChanged = hasChanged;
    }

    public void setIdTokenClaims(String rawIdToken) throws ParseException {
        final Map<String, Object> tokenClaims = SignedJWT.parse(rawIdToken).getJWTClaimsSet().getClaims();
        this.idTokenClaims = tokenClaims;
        this.setGroupsFromIdToken(tokenClaims);
        this.setRolesFromIdToken(idTokenClaims);
        this.setHasChanged(true);
    }

    public void setGroupsFromIdToken(Map<String,Object> idTokenClaims) {
        JSONArray groupsFromToken = (JSONArray) this.idTokenClaims.get("groups");
        if (groupsFromToken != null) {
            this.setGroupsOverage(false);
            this.groups = new ArrayList<>();
            groupsFromToken.forEach(elem -> this.groups.add((String) elem));
        } else {
            JSONObject jsonObj = (JSONObject) idTokenClaims.get("_claim_names");
            if (jsonObj != null && jsonObj.containsKey("groups")) {
                this.setGroupsOverage(true);
            }
        }
        this.setHasChanged(true);
    }

    public void setRolesFromIdToken(Map<String,Object> idTokenClaims) {
        JSONArray rolesFromToken = (JSONArray) idTokenClaims.get("roles");
        if (rolesFromToken != null) {
            this.groups = new ArrayList<>();
            rolesFromToken.forEach(elem -> this.roles.add((String) elem));
            this.setHasChanged(true);
        }
    }

    public void setStateAndNonce(String state, String nonce) {
        this.state = state;
        this.nonce = nonce;
        this.stateDate = new Date();
        this.setHasChanged(true);
    }

    public Map<String, Object> getIdTokenClaims() {
        return this.idTokenClaims;
    }

    public String getNonce() {
        return this.nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getState() {
        return this.state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public Date getStateDate() {
        return this.stateDate;
    }

    private void setGroupsOverage(boolean groupsOverage) {
        this.groupsOverage = groupsOverage;
        this.setHasChanged(true);
    }

}
