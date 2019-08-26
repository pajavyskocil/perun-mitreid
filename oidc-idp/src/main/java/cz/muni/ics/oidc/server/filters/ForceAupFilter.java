package cz.muni.ics.oidc.server.filters;

import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.PerunAttribute;
import cz.muni.ics.oidc.models.PerunUser;
import cz.muni.ics.oidc.server.PerunPrincipal;
import cz.muni.ics.oidc.server.configurations.PerunOidcConfig;
import cz.muni.ics.oidc.server.connectors.PerunConnector;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

public class ForceAupFilter extends GenericFilterBean {

    private final static Logger log = LoggerFactory.getLogger(ForceAupFilter.class);

    @Autowired
    private OAuth2RequestFactory authRequestFactory;

    @Autowired
    private ClientDetailsEntityService clientService;

    @Autowired
    private PerunConnector perunConnector;

    @Autowired
    private PerunOidcConfig perunOidcConfig;

    private static final String REQ_PATTERN = "/authorize";
    private static final String SHIB_IDENTITY_PROVIDER = "Shib-Identity-Provider";


    private RequestMatcher requestMatcher = new AntPathRequestMatcher(REQ_PATTERN);

    private String perunOrgAupsAttrName;
    private String perunUserAupsAttrName;
    private String perunVoAupAttrName;
    private String perunFacilityRequestedAupsAttrName;
    private String perunFacilityVoShortNamesAttrName;

    public String getPerunOrgAupsAttrName() {
        return perunOrgAupsAttrName;
    }

    public void setPerunOrgAupsAttrName(String perunOrgAupsAttrName) {
        this.perunOrgAupsAttrName = perunOrgAupsAttrName;
    }

    public String getPerunUserAupsAttrName() {
        return perunUserAupsAttrName;
    }

    public void setPerunUserAupsAttrName(String perunUserAupsAttrName) {
        this.perunUserAupsAttrName = perunUserAupsAttrName;
    }

    public String getPerunVoAupAttrName() {
        return perunVoAupAttrName;
    }

    public void setPerunVoAupAttrName(String perunVoAupAttrName) {
        this.perunVoAupAttrName = perunVoAupAttrName;
    }

    public String getPerunFacilityRequestedAupsAttrName() {
        return perunFacilityRequestedAupsAttrName;
    }

    public void setPerunFacilityRequestedAupsAttrName(String perunFacilityRequestedAupsAttrName) {
        this.perunFacilityRequestedAupsAttrName = perunFacilityRequestedAupsAttrName;
    }

    public String getPerunFacilityVoShortNamesAttrName() {
        return perunFacilityVoShortNamesAttrName;
    }

    public void setPerunFacilityVoShortNamesAttrName(String perunFacilityVoShortNamesAttrName) {
        this.perunFacilityVoShortNamesAttrName = perunFacilityVoShortNamesAttrName;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        Principal p = request.getUserPrincipal();
        String shibIdentityProvider = perunOidcConfig.getProxyExtSourceName();
        if (shibIdentityProvider == null) {
            shibIdentityProvider = (String) req.getAttribute(SHIB_IDENTITY_PROVIDER);
        }
        PerunPrincipal principal = new PerunPrincipal(p.getName(), shibIdentityProvider);
        PerunUser user = perunConnector.getPreauthenticatedUserId(principal);

        ClientDetailsEntity client = FiltersUtils.extractClient(requestMatcher, request, authRequestFactory, clientService);
        if (client == null) {
            log.debug("Could not fetch client, skip to next filter");
            chain.doFilter(req, res);
            return;
        }

        String clientIdentifier = client.getClientId();

        Facility facility = perunConnector.getFacilityByClientId(clientIdentifier);

        if (facility == null) {
            log.error("Could not find facility with clientID: {}", clientIdentifier);
            log.info("Skipping filter because not able to find facility");
            chain.doFilter(request, response);
            return;
        }

        Map<String, String> newAups = getNewAups(user, facility);

        if (newAups.isEmpty()) {
            log.debug("ForceAupFilter - No required or Vo required Aups for client with clientId {}. Skipping to next filter.", clientIdentifier);
            chain.doFilter(req, res);
        }
    }

    private Map<String, String> getNewAups(PerunUser user, Facility facility) {
        Map<String, String> newAups = new LinkedHashMap<>();
        Map<String, PerunAttribute> facilityAttributes = perunConnector.getFacilityAttributes(facility, new ArrayList<String>(Arrays.asList(perunFacilityRequestedAupsAttrName, perunFacilityVoShortNamesAttrName)));

        PerunAttribute facilityRequiredAups = facilityAttributes.get(perunFacilityRequestedAupsAttrName);
        PerunAttribute facilityVoShortNames = facilityAttributes.get(perunFacilityVoShortNamesAttrName);

        List<String> requiredAups = facilityRequiredAups.valueAsList();
        List<String> voAups = getVoAups(facilityVoShortNames.valueAsList());
        PerunAttribute orgAupsAttr = perunConnector.getEntitylessAttribute(perunOrgAupsAttrName);
        PerunAttribute userAupsAttr = perunConnector.getUserAttribute(user.getId(), perunUserAupsAttrName);
        Map<String, String> userAups = userAupsAttr.valueAsMap();
        Map<String, String> orgAups = orgAupsAttr.valueAsMap();

        if (requiredAups.isEmpty() && voAups.isEmpty()) {
            return newAups;
        }

        if (!orgAups.isEmpty()) {
            for (String key :  requiredAups) {
                String aups = orgAups.get(key);
                logger.debug(aups);
            }
        }

        return newAups;
    }

    private List<String> getVoAups(List<String> voShortNames) {
        List<String> voAups = new ArrayList<>();
        for (String voShortName : voShortNames) {
            Long voId = perunConnector.getVoByShortName(voShortName).getId();

            PerunAttribute voAupAttr = perunConnector.getVoAttribute(voId, perunVoAupAttrName);
            String aup = voAupAttr.valueAsString();

            if (aup != null || !aup.isEmpty()) {
                voAups.add(aup);
            }
        }
        return voAups;
    }

    private function getLatestAup() {

    }
}
