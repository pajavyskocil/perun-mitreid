package cz.muni.ics.oidc.server.connectors.impl;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.TextNode;
import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.Group;
import cz.muni.ics.oidc.models.PerunAttribute;
import cz.muni.ics.oidc.models.PerunUser;
import cz.muni.ics.oidc.models.RichUser;
import cz.muni.ics.oidc.models.Vo;
import cz.muni.ics.oidc.server.PerunPrincipal;
import cz.muni.ics.oidc.server.connectors.Affiliation;
import cz.muni.ics.oidc.server.connectors.PerunConnector;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.DefaultLdapConnectionFactory;
import org.apache.directory.ldap.client.api.DefaultPoolableLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.ldap.client.template.LdapConnectionTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

import java.util.List;
import java.util.Map;

import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;

/**
 * Connects to Perun using LDAP.
 *
 * @author Martin Kuba makub@ics.muni.cz
 */
public class PerunConnectorLdap implements PerunConnector, DisposableBean {

	private final static Logger log = LoggerFactory.getLogger(PerunConnectorLdap.class);

	private static final String OBJECT_CLASS = "objectClass";
	private static final String GIVEN_NAME = "givenName";
	private static final String SN = "sn";
	private static final String CN = "cn";
	private static final String DESCRIPTION = "description";
	private static final String MEMBER_OF = "memberOf";
	private static final String EDU_PERSON_PRINCIPAL_NAMES = "eduPersonPrincipalNames";
	private static final String ASSIGNED_GROUP_ID = "assignedGroupId";
	private static final String OIDC_CLIENT_ID = "OIDCClientID";
	private static final String PERUN_USER = "perunUser";
	private static final String PERUN_USER_ID = "perunUserId";
	private static final String PERUN_RESOURCE = "perunResource";
	private static final String PERUN_FACILITY_ID = "perunFacilityId";
	private static final String PERUN_VO_ID = "perunVoId";
	private static final String PERUN_GROUP_ID = "perunGroupId";
	private static final String PERUN_PARENT_GROUP_ID = "perunParentGroupId";
	private static final String PERUN_UNIQUE_GROUP_NAME = "perunUniqueGroupName";

	private final String baseDN;
	private final LdapConnectionPool pool;
	private final LdapConnectionTemplate ldap;

	private PerunConnector fallbackConnector;

	public PerunConnectorLdap(String ldapHost, String ldapUser, String ldapPassword, long timeoutSecs, String baseDN) {
		this.baseDN = baseDN;
		LdapConnectionConfig config = new LdapConnectionConfig();
		config.setLdapHost(ldapHost);
		config.setLdapPort(636);
		config.setUseSsl(true);
		config.setName(ldapUser);
		config.setCredentials(ldapPassword);
		DefaultLdapConnectionFactory factory = new DefaultLdapConnectionFactory(config);
		factory.setTimeOut(timeoutSecs * 1000L);
		GenericObjectPoolConfig poolConfig = new GenericObjectPoolConfig();
		poolConfig.setTestOnBorrow(true);
		pool = new LdapConnectionPool(new DefaultPoolableLdapConnectionFactory(factory), poolConfig);
		ldap = new LdapConnectionTemplate(pool);
		log.debug("initialized");
	}

	public void setFallbackConnector(PerunConnector fallbackConnector) {
		this.fallbackConnector = fallbackConnector;
	}

	/**
	 * Invoked by a BeanFactory on destruction of a Spring bean.
	 */
	@Override
	public void destroy() {
		log.trace("destroy()");
		if (!pool.isClosed()) {
			pool.close();
		}
	}

	/**
	 * Fetch user based on his principal (extLogin and extSource) from Perun
	 *
	 * @param perunPrincipal principal of user
	 * @return PerunUser with id of found user
	 */
	@Override
	public PerunUser getPreauthenticatedUserId(PerunPrincipal perunPrincipal) {
		log.trace("getPreauthenticatedUserId({})", perunPrincipal);
		FilterBuilder filter = and(equal(OBJECT_CLASS, PERUN_USER), equal(EDU_PERSON_PRINCIPAL_NAMES, perunPrincipal.getExtLogin()));
		return ldap.searchFirst(ldap.newDn("ou=People," + baseDN), filter, SearchScope.ONELEVEL,
				new String[]{PERUN_USER_ID, GIVEN_NAME, SN},
				e -> new PerunUser(Long.parseLong(e.get(PERUN_USER_ID).getString()), e.get(GIVEN_NAME).getString(), e.get(SN).getString()));
	}

	/**
	 * Fetch user identified by userId from Perun
	 *
	 * @param userId identifier of the user
	 * @return RichUser with attributes of found user
	 */
	@Override
	public RichUser getUserAttributes(Long userId) {
		log.trace("getUserAttributes({})", userId);
		RichUser richUser = ldap.lookup(ldap.newDn(PERUN_USER_ID + "=" + userId + ",ou=People," + baseDN), entry -> {
			RichUser r = new RichUser(userId);
			for (Attribute attr : entry) {
				if (attr.isHumanReadable()) {
					if (attr.size() > 1) {
						ArrayNode arrayNode = JsonNodeFactory.instance.arrayNode(attr.size());
						for (Value value : attr) {
							arrayNode.add(value.getString());
						}
						r.getAttributes().put(attr.getUpId(), arrayNode);
					} else {
						String value = attr.get().getString();
						r.getAttributes().put(attr.getUpId(), TextNode.valueOf(value));
					}
				}
			}
			return r;
		});

		log.trace("getUserAttributes({}) returns {}", userId, richUser);
		return richUser;
	}

	@Override
	public Facility getFacilityByClientId(String clientId) {
		log.trace("getFacilityByClientId({})", clientId);
		FilterBuilder filter = and(equal(OBJECT_CLASS, PERUN_RESOURCE), equal(OIDC_CLIENT_ID, clientId));
		Facility facility = ldap.searchFirst(ldap.newDn(baseDN), filter, SearchScope.SUBTREE,
				new String[]{PERUN_FACILITY_ID, DESCRIPTION, CN},
				e -> new Facility(Long.parseLong(e.get(PERUN_FACILITY_ID).getString()),
						e.get(CN).getString(),
						e.get(DESCRIPTION).getString()));

		log.trace("getFacilitiesByClientId({}) returns {}", clientId, facility);
		return facility;
	}

	@Override
	public boolean isMembershipCheckEnabledOnFacility(Facility facility) {
		//TODO cannot be read from LDAP yet, implement after changing LDAP
		log.trace("isMembershipCheckEnabledOnFacility({})", facility);
		boolean b = fallbackConnector.isMembershipCheckEnabledOnFacility(facility);

		log.trace("isMembershipCheckEnabledOnFacility({}) returns {}", facility, b);
		return b;
	}

	@Override
	public boolean canUserAccessBasedOnMembership(Facility facility, Long userId) {
		//TODO implement
		log.trace("canUserAccessBasedOnMembership({}, {})", facility, userId);
		boolean b = fallbackConnector.isMembershipCheckEnabledOnFacility(facility);

		log.trace("canUserAccessBasedOnMembership({}, {}) returns {}", facility, userId, b);
		return b;
	}

	@Override
	public Map<Vo, List<Group>> getGroupsForRegistration(Facility facility, Long userId, List<String> voShortNames) {
		//TODO: cannot be read from LDAP yet, implement after changing LDAP
		log.trace("getGroupsForRegistration({}, {})", facility, userId);
		Map<Vo, List<Group>> res = fallbackConnector.getGroupsForRegistration(facility, userId, voShortNames);

		log.trace("getGroupsForRegistration({}, {}) returns {}", facility, userId, res);
		return res;
	}

	@Override
	public boolean groupWhereCanRegisterExists(Facility facility) {
		//TODO: cannot be read from LDAP yet, implement after changing LDAP
		log.trace("groupWhereCanRegisterExists({})", facility);
		boolean res = fallbackConnector.groupWhereCanRegisterExists(facility);

		log.trace("groupWhereCanRegisterExists({}) returns {}", facility, res);
		return res;
	}

	@Override
	public Map<String, PerunAttribute> getFacilityAttributes(Facility facility, List<String> attributeNames) {
		//TODO: cannot be read from LDAP yet, implement after changing LDAP
		log.trace("getFacilityAttributes({}, {})", facility, attributeNames);
		Map<String, PerunAttribute> attrs = fallbackConnector.getFacilityAttributes(facility, attributeNames);

		log.trace("getFacilityAttributes({}, {}) returns {}", facility, attributeNames, attrs);
		return attrs;
	}

	@Override
	public boolean isUserInGroup(Long userId, Long groupId) {
		//TODO: implement
		return fallbackConnector.isUserInGroup(userId, groupId);
	}

	@Override
	public PerunAttribute getUserAttribute(Long userId, String attributeName) {
		//TODO: implement
		return fallbackConnector.getUserAttribute(userId, attributeName);
	}

	@Override
	public List<Affiliation> getUserExtSourcesAffiliations(Long userId) {
		//TODO: implement
		return fallbackConnector.getUserExtSourcesAffiliations(userId);
	}

	@Override
	public List<Affiliation> getGroupAffiliations(Long userId) {
		//TODO: implement
		return fallbackConnector.getGroupAffiliations(userId);
	}

	@Override
	public PerunAttribute getEntitylessAttribute(String attributeName) {
		//TODO: implement
		return fallbackConnector.getEntitylessAttribute(attributeName);
	}

	@Override
	public PerunAttribute getVoAttribute(Long voId, String attributeName) {
		//TODO: implement
		return fallbackConnector.getVoAttribute(voId, attributeName);
	}

	@Override
	public Vo getVoByShortName(String shortName) {
		//TODO: implement
		return fallbackConnector.getVoByShortName(shortName);
	}
}
