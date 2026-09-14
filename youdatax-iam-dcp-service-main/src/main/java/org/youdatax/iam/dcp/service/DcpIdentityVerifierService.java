package org.youdatax.iam.dcp.service;

import static org.eclipse.edc.iam.decentralizedclaims.spi.SelfIssuedTokenConstants.PRESENTATION_TOKEN_CLAIM;
import static org.eclipse.edc.jwt.spi.JwtRegisteredClaimNames.ISSUER;
import static org.eclipse.edc.spi.result.Result.failure;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import org.eclipse.edc.iam.decentralizedclaims.spi.ClaimTokenCreatorFunction;
import org.eclipse.edc.iam.decentralizedclaims.spi.PresentationRequestService;
import org.eclipse.edc.iam.decentralizedclaims.spi.validation.TokenValidationAction;
import org.eclipse.edc.iam.verifiablecredentials.spi.VerifiableCredentialValidationService;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiableCredential;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiablePresentation;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiablePresentationContainer;
import org.eclipse.edc.iam.verifiablecredentials.spi.validation.CredentialValidationRule;
import org.eclipse.edc.spi.iam.ClaimToken;
import org.eclipse.edc.spi.iam.TokenRepresentation;
import org.eclipse.edc.spi.iam.VerificationContext;
import org.eclipse.edc.spi.result.Result;

public class DcpIdentityVerifierService {
    private final Function<String, String> didResolver;
    private final TokenValidationAction tokenValidationAction;
    private final PresentationRequestService presentationRequestService;
    private final ClaimTokenCreatorFunction claimTokenCreatorFunction;   
    private final VerifiableCredentialValidationService verifiableCredentialValidationService;
    
	public DcpIdentityVerifierService(Function<String, String> didResolver,
            TokenValidationAction tokenValidationAction,
            PresentationRequestService presentationRequestService,
            ClaimTokenCreatorFunction claimTokenCreatorFunction,
            VerifiableCredentialValidationService verifiableCredentialValidationService) {
		
        this.didResolver = didResolver;
        this.tokenValidationAction = tokenValidationAction;
        this.presentationRequestService = presentationRequestService;
        this.claimTokenCreatorFunction = claimTokenCreatorFunction;
        this.verifiableCredentialValidationService = verifiableCredentialValidationService;		
	}
	
    //@Override
    public Result<ClaimToken> verifyJwtToken(String participantContextId, TokenRepresentation tokenRepresentation, VerificationContext context) {
        // strip out the "Bearer " prefix
        var token = tokenRepresentation.getToken();
        if (!token.startsWith("Bearer ")) {
            return failure("Token is not a Bearer token");
        }
        token = token.replace("Bearer ", "").trim();
        tokenRepresentation = tokenRepresentation.toBuilder().token(token).build();
        var claimTokenResult = tokenValidationAction.validate(participantContextId, tokenRepresentation);

        if (claimTokenResult.failed()) {
            return claimTokenResult.mapEmpty();
        }

        var claimToken = claimTokenResult.getContent();
        var accessToken = claimToken.getStringClaim(PRESENTATION_TOKEN_CLAIM);
        var issuer = claimToken.getStringClaim(ISSUER);

        var myOwnDid = didResolver.apply(participantContextId);
        var requestedScopes = context.getScopes().stream().toList();

        var vpResponse = presentationRequestService.requestPresentation(participantContextId, myOwnDid, issuer, accessToken, requestedScopes);
        if (vpResponse.failed()) {
            return vpResponse.mapEmpty();
        }

        var presentations = vpResponse.getContent();

        // check all requested credentials are present
        var result = validateRequestedCredentials(presentations, requestedScopes)
                .compose(unused -> verifiableCredentialValidationService.validate(presentations, myOwnDid, getAdditionalValidations()));


        return result
                .compose(u -> verifyPresentationIssuer(issuer, presentations))
                .compose(u -> claimTokenCreatorFunction.apply(presentations.stream().map(p -> p.presentation().getCredentials().stream())
                        .reduce(Stream.empty(), Stream::concat)
                        .toList()));
    }
    
    private Result<Void> validateRequestedCredentials(List<VerifiablePresentationContainer> presentations, List<String> requestedScopes) {
        var allCreds = presentations.stream()
                .flatMap(p -> p.presentation().getCredentials().stream())
                .toList();
        if (requestedScopes.size() > allCreds.size()) {
            return Result.failure("Number of requested credentials does not match the number of returned credentials");
        }

        var types = allCreds.stream().map(VerifiableCredential::getType)
                .flatMap(Collection::stream)
                .distinct()
                .toList();


        return requestedScopes.stream().allMatch(scope -> types.stream().anyMatch(scope::contains)) ?
                Result.success() :
                Result.failure("Not all requested credentials are present in the presentation response");
    }  
    
    private Collection<? extends CredentialValidationRule> getAdditionalValidations() {
        return Collections.emptyList();
    }
    
    /**
     * Checks that the issuer in the SI token == VP token issuer for all presentations
     */
    private Result<Void> verifyPresentationIssuer(String expectedIssuer, List<VerifiablePresentationContainer> presentationContainers) {

        var issuers = presentationContainers.stream().map(VerifiablePresentationContainer::presentation)
                .map(VerifiablePresentation::getHolder)
                .toList();

        if (issuers.stream().allMatch(expectedIssuer::equals)) {
            return Result.success();
        } else {
            return Result.failure("Returned presentations contains invalid issuer. Expected %s found %s".formatted(expectedIssuer, issuers));
        }
    }    
}
