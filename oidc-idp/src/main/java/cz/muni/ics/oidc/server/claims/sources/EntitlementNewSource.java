package cz.muni.ics.oidc.server.claims.sources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.google.common.net.UrlEscapers;
import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.Group;
import cz.muni.ics.oidc.models.PerunAttributeValue;
import cz.muni.ics.oidc.server.adapters.PerunAdapter;
import cz.muni.ics.oidc.server.claims.ClaimSource;
import cz.muni.ics.oidc.server.claims.ClaimSourceInitContext;
import cz.muni.ics.oidc.server.claims.ClaimSourceProduceContext;
import cz.muni.ics.oidc.server.claims.ClaimUtils;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.util.*;

public class EntitlementNewSource extends ClaimSource {

    public static final Logger log = LoggerFactory.getLogger(EntitlementNewSource.class);

    private static final String FORWARDED_ENTITLEMENTS = "forwardedEntitlements";
    private static final String RESOURCE_CAPABILITIES = "resourceCapabilities";
    private static final String FACILITY_CAPABILITIES = "facilityCapabilities";
    private static final String PREFIX = "prefix";
    private static final String AUTHORITY = "authority";
    private static final String MEMBERS = "members";

    private final String forwardedEntitlements;
    private final String resourceCapabilities;
    private final String facilityCapabilities;
    private final String prefix;
    private final String authority;

    public EntitlementNewSource(ClaimSourceInitContext ctx) {
        super(ctx);
        this.forwardedEntitlements = ClaimUtils.fillStringPropertyOrNoVal(FORWARDED_ENTITLEMENTS, ctx);
        this.resourceCapabilities = ClaimUtils.fillStringPropertyOrNoVal(RESOURCE_CAPABILITIES, ctx);
        this.facilityCapabilities = ClaimUtils.fillStringPropertyOrNoVal(FACILITY_CAPABILITIES, ctx);
        this.prefix = ClaimUtils.fillStringPropertyOrNoVal(PREFIX, ctx);
        if (!ClaimUtils.isPropSet(this.prefix)) {
            throw new IllegalArgumentException("Missing mandatory configuration option - prefix");
        }
        this.authority = ClaimUtils.fillStringPropertyOrNoVal(AUTHORITY, ctx);
        if (!ClaimUtils.isPropSet(this.authority)) {
            throw new IllegalArgumentException("Missing mandatory configuration option - authority");
        }
    }

    @Override
    public JsonNode produceValue(ClaimSourceProduceContext pctx) {
        log.error("START");
        PerunAdapter perunConnector = pctx.getPerunAdapter();
        ClientDetailsEntity client = pctx.getClient();
        Facility facility = null;

        Set<String> entitlements = new TreeSet<>();


        if (client != null) {
            String clientId = client.getClientId();
            facility = perunConnector.getFacilityByClientId(clientId);
            log.error("found facility ({}) for client_id ({})", facility, clientId);
        }

        Set<Group> userGroups = new HashSet<>();
        if (facility != null) {
            userGroups = perunConnector.getGroupsWhereUserIsActiveWithUniqueNames(facility.getId(),
                    pctx.getPerunUserId());
            log.error("Found user groups: {}", userGroups);
        }

        this.fillUuidEntitlements(userGroups, entitlements);

        Map<Long, String> idToNameMap = new HashMap<>();
        userGroups.forEach(g -> {
            String uniqueName = g.getUniqueGroupName();
            if (StringUtils.hasText(uniqueName) && "members".equals(g.getName())) {
                uniqueName = uniqueName.replace(":members", "");
                g.setUniqueGroupName(uniqueName);
            }

            idToNameMap.put(g.getId(), g.getUniqueGroupName());
        });

        if (idToNameMap != null && !idToNameMap.values().isEmpty()) {
            this.fillEntitlementsFromGroupNames(idToNameMap.values(), entitlements);
            log.trace("Added entitlements for group names, current value: {}", entitlements);
        }

        if (facility != null) {
            this.fillCapabilities(facility, pctx, idToNameMap, entitlements);
            log.trace("Added entitlements for capabilities, current value: {}", entitlements);
        }

        if (ClaimUtils.isPropSet(this.forwardedEntitlements)) {
            this.fillForwardedEntitlements(pctx, entitlements);
            log.error("Added forwarded entitlements, current value: {}", entitlements);
        }

        ArrayNode result = JsonNodeFactory.instance.arrayNode();
        for (String entitlement: entitlements) {
            result.add(entitlement);
        }

        return result;
    }

    private void fillEntitlementsFromGroupNames(Collection<String> groupNames, Set<String> entitlements) {
        for (String fullGname: groupNames) {
            if (fullGname == null || fullGname.trim().isEmpty()) {
                continue;
            }

            String[] parts = fullGname.split(":", 2);
            if (parts.length == 2 && StringUtils.hasText(parts[1]) && MEMBERS.equals(parts[1])) {
                parts[1] = parts[1].replace(MEMBERS, "");
            }

            String gname = parts[0];
            if (parts.length == 2 && StringUtils.hasText(parts[1])) {
                gname += (':' + parts[1]);
            }
            entitlements.add(wrapGroupNameToAARC(gname));
        }
    }

    private void fillUuidEntitlements(Set<Group> userGroups, Set<String> entitlements) {
        for (Group group : userGroups) {
            log.error(group.getUuid());
            String uniqueName = group.getUniqueGroupName();
            if (StringUtils.hasText(uniqueName) && MEMBERS.equals(group.getName())) {
                uniqueName = uniqueName.replace(":members", "");
            }
            String entitlement = group.getUuid() + "?uniqueName=" + uniqueName;
            entitlements.add(wrapGroupEntitlementToAARC(entitlement));
        }
    }

    private void fillCapabilities(Facility facility, ClaimSourceProduceContext pctx,
                                  Map<Long, String> idToGnameMap, Set<String> entitlements) {
        Set<String> resultCapabilities = pctx.getPerunAdapter()
                .getCapabilities(facility, idToGnameMap,
                        ClaimUtils.isPropSet(this.facilityCapabilities) ? facilityCapabilities : null,
                        ClaimUtils.isPropSet(this.resourceCapabilities)? resourceCapabilities: null);

        for (String capability : resultCapabilities) {
            entitlements.add(wrapCapabilityToAARC(capability));
        }
    }

    private void fillForwardedEntitlements(ClaimSourceProduceContext pctx, Set<String> entitlements) {
        PerunAttributeValue forwardedEntitlementsVal = pctx.getPerunAdapter()
                .getUserAttributeValue(pctx.getPerunUserId(), this.forwardedEntitlements);
        if (forwardedEntitlementsVal != null && !forwardedEntitlementsVal.isNullValue()) {
            JsonNode eduPersonEntitlementJson = forwardedEntitlementsVal.valueAsJson();
            for (int i = 0; i < eduPersonEntitlementJson.size(); i++) {
                log.debug("Added forwarded entitlement: {}", eduPersonEntitlementJson.get(i).asText());
                entitlements.add(eduPersonEntitlementJson.get(i).asText());
            }
        }
    }

    private String wrapGroupNameToAARC(String groupName) {
        return prefix + "group:" + UrlEscapers.urlPathSegmentEscaper().escape(groupName) + "#" + authority;
    }

    private String wrapGroupEntitlementToAARC(String entitlement) {
        return prefix + "groupUuid:" + UrlEscapers.urlPathSegmentEscaper().escape(entitlement) + "#" + authority;
    }

    private String wrapCapabilityToAARC(String capability) {
        return prefix + UrlEscapers.urlPathSegmentEscaper().escape(capability) + "#" + authority;
    }

}
