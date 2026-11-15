package org.youdatax.iam.dcp.service;

import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.AUDIENCE;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.ISSUER;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.SCOPE;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.SUBJECT;
import static org.eclipse.edc.spi.result.Result.failure;
import static org.eclipse.edc.spi.result.Result.success;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.eclipse.edc.iam.decentralizedclaims.spi.SecureTokenService;
import org.eclipse.edc.spi.iam.TokenParameters;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.util.string.StringUtils;

public class DcpIdentityHolderService {
    private static final String SCOPE_STRING_REGEX = "(.+):(.+):(read|write|\\*)";
    
	private final SecureTokenService secureTokenService;
    private final Function<String, String> didResolver;
    
    public DcpIdentityHolderService(SecureTokenService secureTokenService, Function<String, String> didResolver) {
        this.secureTokenService = secureTokenService;
        this.didResolver = didResolver;    	
    }
    
    //@Override
    public Result<TokenRepresentation> obtainClientCredentials(String participantContextId, TokenParameters parameters) {
        var aud = parameters.getStringClaim(AUDIENCE);
        var scope = parameters.getStringClaim(SCOPE);
        parameters = TokenParameters.Builder.newInstance()
                .claims(AUDIENCE, aud)
                .claims(SCOPE, scope)
                .claims(parameters.getClaims())
                .build();

        var scopeValidationResult = validateScope(scope);

        if (scopeValidationResult.failed()) {
            return failure(scopeValidationResult.getFailureMessages());
        }

        // create claims for the STS
        var claims = new HashMap<String, Object>();
        parameters.getClaims().forEach((k, v) -> claims.replace(k, v.toString()));

        var myOwnDid = didResolver.apply(participantContextId);

        claims.putAll(Map.of(
                ISSUER, myOwnDid,
                SUBJECT, myOwnDid,
                AUDIENCE, parameters.getStringClaim(AUDIENCE)));

        return secureTokenService.createToken(participantContextId, claims, scope)
                .map(originalToken -> originalToken.toBuilder()
                        .token("Bearer " + originalToken.getToken())
                        .build());
    }
    
    private Result<Void> validateScope(String scope) {
        if (StringUtils.isNullOrBlank(scope)) {
            return failure("Scope string invalid: input string was null or empty");
        }
        return scope.matches(SCOPE_STRING_REGEX) ?
                success() :
                failure("Scope string invalid: '%s' does not match regex %s".formatted(scope, SCOPE_STRING_REGEX));
    }
}
