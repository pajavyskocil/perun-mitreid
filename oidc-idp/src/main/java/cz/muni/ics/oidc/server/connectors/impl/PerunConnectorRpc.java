package cz.muni.ics.oidc.server.connectors.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.ImmutableMap;
import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.Group;
import cz.muni.ics.oidc.models.Mapper;
import cz.muni.ics.oidc.models.Member;
import cz.muni.ics.oidc.models.PerunAttribute;
import cz.muni.ics.oidc.models.PerunUser;
import cz.muni.ics.oidc.models.RichUser;
import cz.muni.ics.oidc.models.Vo;
import cz.muni.ics.oidc.server.PerunPrincipal;
import cz.muni.ics.oidc.server.connectors.Affiliation;
import cz.muni.ics.oidc.server.connectors.PerunConnector;
import org.apache.http.HeaderElement;
import org.apache.http.HeaderElementIterator;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ConnectionKeepAliveStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeaderElementIterator;
import org.apache.http.protocol.HTTP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.InterceptingClientHttpRequestFactory;
import org.springframework.http.client.support.BasicAuthorizationInterceptor;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Connects to Perun via RPC.
 *
 * @author Martin Kuba makub@ics.muni.cz
 * @author Dominik František Bučík bucik@ics.muni.cz
 * @author Peter Jancus jancus@ics.muni.cz
 */
public class PerunConnectorRpc implements PerunConnector {

	private final static Logger log = LoggerFactory.getLogger(PerunConnectorRpc.class);

	private String perunUrl;
	private String perunUser;
	private String perunPassword;
	private String oidcClientIdAttr;
	private String oidcCheckMembershipAttr;
	private RestTemplate restTemplate;

	public void setPerunUrl(String perunUrl) {
		log.trace("setting perunUrl to {}", perunUrl);
		this.perunUrl = perunUrl;
	}

	public void setPerunUser(String perunUser) {
		log.trace("setting perunUser to {}", perunUser);
		this.perunUser = perunUser;
	}

	public void setPerunPassword(String perunPassword) {
		log.trace("setting perunPassword");
		this.perunPassword = perunPassword;
	}

	public void setOidcClientIdAttr(String oidcClientIdAttr) {
		log.trace("setting OIDCClientID attr shortName");
		this.oidcClientIdAttr = oidcClientIdAttr;
	}

	public void setOidcCheckMembershipAttr(String oidcCheckMembershipAttr) {
		log.trace("setting OIDCCheckGroupMembership attr shortName");
		this.oidcCheckMembershipAttr = oidcCheckMembershipAttr;
	}

	@PostConstruct
	public void postInit() {
		restTemplate = new RestTemplate();
		//HTTP connection pooling, see https://howtodoinjava.com/spring-restful/resttemplate-httpclient-java-config/
		RequestConfig requestConfig = RequestConfig.custom()
				.setConnectionRequestTimeout(30000) // The timeout when requesting a connection from the connection manager
				.setConnectTimeout(30000) // Determines the timeout in milliseconds until a connection is established
				.setSocketTimeout(60000) // The timeout for waiting for data
				.build();
		PoolingHttpClientConnectionManager poolingConnectionManager = new PoolingHttpClientConnectionManager();
		poolingConnectionManager.setMaxTotal(20); // maximum connections total
		poolingConnectionManager.setDefaultMaxPerRoute(18);
		ConnectionKeepAliveStrategy connectionKeepAliveStrategy = (response, context) -> {
			HeaderElementIterator it = new BasicHeaderElementIterator
					(response.headerIterator(HTTP.CONN_KEEP_ALIVE));
			while (it.hasNext()) {
				HeaderElement he = it.nextElement();
				String param = he.getName();
				String value = he.getValue();

				if (value != null && param.equalsIgnoreCase("timeout")) {
					return Long.parseLong(value) * 1000;
				}
			}
			return 20000L;
		};
		CloseableHttpClient httpClient = HttpClients.custom()
				.setDefaultRequestConfig(requestConfig)
				.setConnectionManager(poolingConnectionManager)
				.setKeepAliveStrategy(connectionKeepAliveStrategy)
				.build();
		HttpComponentsClientHttpRequestFactory poolingRequestFactory = new HttpComponentsClientHttpRequestFactory();
		poolingRequestFactory.setHttpClient(httpClient);
		//basic authentication
		List<ClientHttpRequestInterceptor> interceptors =
				Collections.singletonList(new BasicAuthorizationInterceptor(perunUser, perunPassword));
		InterceptingClientHttpRequestFactory authenticatingRequestFactory = new InterceptingClientHttpRequestFactory(poolingRequestFactory, interceptors);
		restTemplate.setRequestFactory(authenticatingRequestFactory);
	}

	@Override
	public PerunUser getPreauthenticatedUserId(PerunPrincipal perunPrincipal) {
		log.trace("getPreauthenticatedUserId({})", perunPrincipal);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("extLogin", perunPrincipal.getExtLogin());
		map.put("extSourceName", perunPrincipal.getExtSourceName());

		PerunUser res = Mapper.mapPerunUser(makeRpcCall("/usersManager/getUserByExtSourceNameAndExtLogin", map));
		log.trace("getPreauthenticatedUserId({}) returns: {}", perunPrincipal, res);
		return res;
	}

	@Override
	public RichUser getUserAttributes(Long userId) {
		log.trace("getUserAttributes({})", userId);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("user", userId);

		RichUser res = Mapper.mapRichUser(makeRpcCall("/usersManager/getRichUserWithAttributes", map));
		log.trace("getUserAttributes({}) returns: {}", userId, res);
		return res;
	}

	@Override
	public Facility getFacilityByClientId(String clientId) {
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("attributeName", oidcClientIdAttr);
		map.put("attributeValue", clientId);
		JsonNode jsonNode = makeRpcCall("/facilitiesManager/getFacilitiesByAttribute", map);

		Facility facility = (jsonNode.size() > 0) ? Mapper.mapFacility(jsonNode.get(0)) : null;
		log.trace("getFacilitiesByClientId({}) returns {}", clientId, facility);
		return facility;
	}

	@Override
	public boolean isMembershipCheckEnabledOnFacility(Facility facility) {
		log.trace("isMembershipCheckEnabledOnFacility({})", facility);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("facility", facility.getId());
		map.put("attributeName", oidcCheckMembershipAttr);
		JsonNode res = makeRpcCall("/attributesManager/getAttribute", map);

		boolean result = res.get("value").asBoolean(false);
		log.trace("isMembershipCheckEnabledOnFacility({}) returns {}", facility, result);
		return result;
	}

	@Override
	public boolean canUserAccessBasedOnMembership(Facility facility, Long userId) {
		log.trace("canUserAccessBasedOnMembership({}, {})", facility, userId);
		List<Group> activeGroups = getGroupsWhereUserIsActive(facility, userId);

		boolean res = (activeGroups != null && !activeGroups.isEmpty());
		log.trace("canUserAccessBasedOnMembership({}, {}) returns: {}", facility, userId, res);
		return res;
	}

	@Override
	public Map<Vo, List<Group>> getGroupsForRegistration(Facility facility, Long userId, List<String> voShortNames) {
		log.trace("getGroupsForRegistration({}, {}, {})", facility, userId, voShortNames);
		List<Vo> vos = getVosByShortNames(voShortNames);
		Map<Long, Vo> vosMap = convertVoListToMap(vos);
		List<Member> userMembers = getMembersByUser(userId);
		userMembers = new ArrayList<>(new HashSet<>(userMembers));

		//Filter out vos where member is other than valid or expired. These vos cannot be used for registration
		Map<Long, String> memberVoStatuses = convertMembersListToStatusesMap(userMembers);
		Map<Long, Vo> vosForRegistration = new HashMap<>();
		for (Map.Entry<Long, Vo> entry : vosMap.entrySet()) {
			if (memberVoStatuses.containsKey(entry.getKey())) {
				String status = memberVoStatuses.get(entry.getKey());
				if (status.equalsIgnoreCase("VALID") || status.equalsIgnoreCase("EXPIRED")) {
					vosForRegistration.put(entry.getKey(), entry.getValue());
				}
			} else {
				vosForRegistration.put(entry.getKey(), entry.getValue());
			}
		}

		// filter groups only if their VO is in the allowed VOs and if they have registration form
		List<Group> allowedGroups = getAllowedGroups(facility);
		List<Group> groupsForRegistration = allowedGroups.stream()
				.filter(group -> vosForRegistration.containsKey(group.getVoId()) && getApplicationForm(group))
				.collect(Collectors.toList());

		// create map for processing
		Map<Vo, List<Group>> result = new HashMap<>();
		for (Group group : groupsForRegistration) {
			Vo vo = vosMap.get(group.getVoId());
			if (!result.containsKey(vo)) {
				result.put(vo, new ArrayList<>());
			}
			List<Group> list = result.get(vo);
			list.add(group);
		}

		log.trace("getGroupsForRegistration({}, {}, {}) returns: {}", facility, userId, voShortNames, result);
		return result;
	}

	private Map<Long, String> convertMembersListToStatusesMap(List<Member> userMembers) {
		Map<Long, String> res = new HashMap<>();
		for (Member m : userMembers) {
			res.put(m.getVoId(), m.getStatus());
		}

		return res;
	}

	@Override
	public boolean groupWhereCanRegisterExists(Facility facility) {
		log.trace("groupsWhereCanRegisterExists({})", facility);
		List<Group> allowedGroups = getAllowedGroups(facility);

		if (allowedGroups != null && !allowedGroups.isEmpty()) {
			for (Group group : allowedGroups) {
				if (getApplicationForm(group)) {
					log.trace("groupsWhereCanRegisterExists({}) returns: true", facility);
					return true;
				}
			}
		}

		log.trace("groupsWhereCanRegisterExists({}) returns: false", facility);
		return false;
	}

	@Override
	public Map<String, PerunAttribute> getFacilityAttributes(Facility facility, List<String> attributeNames) {
		log.trace("getFacilityAttributes({}, {})", facility, attributeNames);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("facility", facility.getId());
		map.put("attrNames", attributeNames);
		JsonNode res = makeRpcCall("/attributesManager/getAttributes", map);

		Map<String, PerunAttribute> attrs = Mapper.mapAttributes(res);
		log.trace("getFacilityAttributes({}, {}) returns: {}", facility, attributeNames, attrs);
		return attrs;
	}

	@Override
	public boolean isUserInGroup(Long userId, Long groupId) {
		Group group = Mapper.mapGroup(makeRpcCall("/groupsManager/getGroupById", ImmutableMap.of("id", groupId)));
		Member member = Mapper.mapMember(makeRpcCall("/membersManager/getMemberByUser", ImmutableMap.of("vo", group.getVoId(), "user", userId)));
		JsonNode res = makeRpcCall("/groupsManager/isGroupMember", ImmutableMap.of("group", groupId, "member", member.getId()));
		boolean result = res.asBoolean(false);
		log.trace("isUserInGroup(userId={},group={}) returns {}", userId, group.getName(), result);
		return result;
	}

	@Override
	public PerunAttribute getUserAttribute(Long userId, String attributeName) {
		return Mapper.mapAttribute(makeRpcCall("/attributesManager/getAttribute", ImmutableMap.of("user", userId, "attributeName", attributeName)));
	}

	@Override
	public List<Affiliation> getUserExtSourcesAffiliations(Long userId) {
		log.trace("getUserExtSourcesAffiliations(user={})", userId);
		String attributeName = "urn:perun:ues:attribute-def:def:affiliation";
		ArrayNode listOfUes = (ArrayNode) makeRpcCall("/usersManager/getUserExtSources", ImmutableMap.of("user", userId));
		List<Affiliation> affiliations = new ArrayList<>();
		for (JsonNode ues : listOfUes) {
			JsonNode extSource = ues.path("extSource");
			if (extSource.path("type").asText().equals("cz.metacentrum.perun.core.impl.ExtSourceIdp")) {
				long id = ues.path("id").asLong();
				String login = ues.path("login").asText();
				long asserted = Timestamp.valueOf(ues.path("lastAccess").asText()).getTime() / 1000L;
				String name = extSource.path("name").asText();
				log.trace("ues id={},shortName={},login={}", id, name, login);
				PerunAttribute perunAttribute = Mapper.mapAttribute(makeRpcCall("/attributesManager/getAttribute", ImmutableMap.of("userExtSource", id, "attributeName", attributeName)));
				String value = perunAttribute.valueAsString();
				if (value != null) {
					for (String v : value.split(";")) {
						Affiliation affiliation = new Affiliation(name, v, asserted);
						log.debug("found {} from IdP {} with modif time {}", v, name, perunAttribute.getValueModifiedAt());
						affiliations.add(affiliation);
					}
				}
			}
		}
		return affiliations;
	}

	@Override
	public List<Affiliation> getGroupAffiliations(Long userId) {
		log.trace("getGroupAffiliations(user={})", userId);
		List<Affiliation> affiliations = new ArrayList<>();
		for (Member member : Mapper.mapMembers(makeRpcCall("/membersManager/getMembersByUser", ImmutableMap.of("user", userId)))) {
			if ("VALID".equals(member.getStatus())) {
				for (Group group : Mapper.mapGroups(makeRpcCall("/groupsManager/getMemberGroups", ImmutableMap.of("member", member.getId())))) {
					PerunAttribute attr = Mapper.mapAttribute(makeRpcCall("/attributesManager/getAttribute", ImmutableMap.of("group", group.getId(), "attributeName", "urn:perun:group:attribute-def:def:groupAffiliations")));
					if (attr.getValue() != null) {
						long linuxTime = System.currentTimeMillis() / 1000L;
						for (String value : attr.valueAsList()) {
							Affiliation affiliation = new Affiliation(null, value, linuxTime);
							log.debug("found {} on group {}", value, group.getName());
							affiliations.add(affiliation);
						}
					}
				}
			}
		}
		return affiliations;
	}

	@Override
	public PerunAttribute getEntitylessAttribute(String attributeName) {
		log.trace("getEntitylessAttribute({})", attributeName);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("attrName", attributeName);
		return Mapper.mapAttribute(makeRpcCall("/attributesManager/getEntitylessAttributes", map));
	}

	@Override
	public PerunAttribute getVoAttribute(Long voId, String attributeName) {
		log.trace("getVoAttribute(voId:{}, attributeName:{})",voId, attributeName);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("vo", voId);
		map.put("attrName", attributeName);
		return Mapper.mapAttribute(makeRpcCall("/attributesManager/getAttribute", map));
	}

	public PerunAttribute getFacilityAttribute(Facility facility, String attributeName) {
		log.trace("getFacilityAttribute({}, {})", facility, attributeName);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("facility", facility.getId());
		map.put("attributeName", attributeName);
		JsonNode res = makeRpcCall("/attributesManager/getAttribute", map);

		PerunAttribute attr = Mapper.mapAttribute(res);
		log.trace("getFacilityAttribute({}, {}) returns: {}", facility, attributeName, attr);
		return attr;
	}

	private List<Member> getMembersByUser(Long userId) {
		log.trace("getMemberByUser({})", userId);
		Map<String, Object> params = new LinkedHashMap<>();
		params.put("user", userId);
		JsonNode jsonNode = makeRpcCall("/membersManager/getMembersByUser", params);

		List<Member> userMembers = Mapper.mapMembers(jsonNode);
		log.trace("getMembersByUser({}) returns: {}", userId, userMembers);
		return userMembers;
	}

	private List<Vo> getVosByShortNames(List<String> voShortNames) {
		log.trace("getVosByShortNames({})", voShortNames);
		List<Vo> vos = new ArrayList<>();
		for (String shortName : voShortNames) {
			Vo vo = getVoByShortName(shortName);
			vos.add(vo);
		}

		log.trace("getVosByShortNames({}) returns: {}", voShortNames, vos);
		return vos;
	}

	public Vo getVoByShortName(String shortName) {
		log.trace("getVoByShortName({})", shortName);
		Map<String, Object> params = new LinkedHashMap<>();
		params.put("shortName", shortName);
		JsonNode jsonNode = makeRpcCall("/vosManager/getVoByShortName", params);

		Vo vo = Mapper.mapVo(jsonNode);
		log.trace("getVoByShortName({}) returns: {}", shortName, vo);
		return vo;
	}

	private List<Group> getAllowedGroups(Facility facility) {
		log.trace("getAllowedGroups({})", facility);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("facility", facility.getId());
		JsonNode jsonNode = makeRpcCall("/facilitiesManager/getAllowedGroups", map);
		List<Group> result = new ArrayList<>();
		for (int i = 0; i < jsonNode.size(); i++) {
			JsonNode groupNode = jsonNode.get(i);
			result.add(Mapper.mapGroup(groupNode));
		}

		log.trace("getAllowedGroups({}) returns: {}", facility, result);
		return result;
	}

	private boolean getApplicationForm(Group group) {
		log.trace("getApplicationForm({})", group);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("group", group.getId());
		try {
			if (group.getName().equalsIgnoreCase("members")) {
				log.trace("getApplicationForm({}) continues to call regForm for VO {}", group, group.getVoId());
				return getApplicationForm(group.getVoId());
			} else {
				makeRpcCall("/registrarManager/getApplicationForm", map);
			}
		} catch (Exception e) {
			// when group does not have form exception is thrown. Every error thus is supposed as group without form
			// this method will be used after calling other RPC methods - if RPC is not available other methods should discover it first
			log.trace("getApplicationForm({}) returns: false", group);
			return false;
		}

		log.trace("getApplicationForm({}) returns: true", group);
		return true;
	}

	private boolean getApplicationForm(Long voId) {
		log.trace("getApplicationForm({})", voId);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("vo", voId);
		try {
			makeRpcCall("/registrarManager/getApplicationForm", map);
		} catch (Exception e) {
			// when vo does not have form exception is thrown. Every error thus is supposed as vo without form
			// this method will be used after calling other RPC methods - if RPC is not available other methods should discover it first
			log.trace("getApplicationForm({}) returns: false", voId);
			return false;
		}

		log.trace("getApplicationForm({}) returns: true", voId);
		return true;
	}

	private List<Group> getGroupsWhereUserIsActive(Facility facility, Long userId) {
		log.trace("getGroupsWhereUserIsActive({}, {})", facility, userId);
		Map<String, Object> map = new LinkedHashMap<>();
		map.put("facility", facility.getId());
		map.put("user", userId);
		JsonNode jsonNode = makeRpcCall("/usersManager/getGroupsWhereUserIsActive", map);

		List<Group> res = Mapper.mapGroups(jsonNode);
		log.trace("getGroupsWhereUserIsActive({}, {}) returns: {}", facility, userId, res);
		return res;
	}

	private Map<Long, Vo> convertVoListToMap(List<Vo> vos) {
		Map<Long, Vo> map = new HashMap<>();
		for (Vo vo : vos) {
			map.put(vo.getId(), vo);
		}

		return map;
	}

	private JsonNode makeRpcCall(String urlPart, Map<String, Object> map) {
		String actionUrl = perunUrl + "/json" + urlPart;
		//make the call
		try {
			log.trace("calling {} with {}", actionUrl, map);
			return restTemplate.postForObject(actionUrl, map, JsonNode.class);
		} catch (HttpClientErrorException ex) {
			MediaType contentType = ex.getResponseHeaders().getContentType();
			String body = ex.getResponseBodyAsString();
			log.error("HTTP ERROR " + ex.getRawStatusCode() + " URL " + actionUrl + " Content-Type: " + contentType);
			if ("json".equals(contentType.getSubtype())) {
				try {
					log.error(new ObjectMapper().readValue(body, JsonNode.class).path("message").asText());
				} catch (IOException e) {
					log.error("cannot parse error message from JSON", e);
				}
			} else {
				log.error(ex.getMessage());
			}
			throw new RuntimeException("cannot connect to Perun RPC", ex);
		}
	}

}
