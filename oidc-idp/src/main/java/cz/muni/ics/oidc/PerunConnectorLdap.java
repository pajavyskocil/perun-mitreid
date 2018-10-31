package cz.muni.ics.oidc;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.TextNode;
import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.Group;
import cz.muni.ics.oidc.models.PerunUser;
import cz.muni.ics.oidc.models.RichUser;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
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

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

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

	/**
	 * Invoked by a BeanFactory on destruction of a Spring bean.
	 */
	@Override
	public void destroy() {
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
		RichUser richUser = ldap.lookup(ldap.newDn(PERUN_USER_ID + "=" + userId + ",ou=People," + baseDN), entry -> {
			RichUser r = new RichUser(userId);
			for (Attribute attr : entry) {
				if (attr.isHumanReadable()) {
					if (attr.size() > 1) {
						ArrayNode arrayNode = JsonNodeFactory.instance.arrayNode(attr.size());
						for (Value value : attr) {
							arrayNode.add(value.getValue());
						}
						r.getAttributes().put(attr.getUpId(), arrayNode);
					} else {
						String value = attr.get().getValue();
						r.getAttributes().put(attr.getUpId(), TextNode.valueOf(value));
					}
				}
			}
			return r;
		});
		log.trace("getUserAttributes({}) returns {}", userId, richUser);
		return richUser;
	}

	private PerunConnector fallbackConnector;

	public void setFallbackConnector(PerunConnector fallbackConnector) {
		this.fallbackConnector = fallbackConnector;
	}

	@Override
	public Facility getFacilityByClientId(String clientId) {
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
		boolean b = fallbackConnector.isMembershipCheckEnabledOnFacility(facility);
		log.trace("isMembershipCheckEnabledOnFacility({}) returns {}", facility, b);
		return b;
	}

	@Override
	public boolean isUserAllowedOnFacility(Facility facility, Long userId) {
		if (this.getUserGroupsAllowedOnFacility(facility, userId).isEmpty()) {
			log.debug("groupCheckForFacility(facility={},user={}) - no group matches", facility.getId(), userId);
			return false;
		}
		return true;
	}

	@Override
	public Set<Group> getUserGroupsAllowedOnFacility(Facility facility, Long userId) {
		Set<String> facilityGroupsDNs = getFacilityGroupsDNs(facility);
		Set<String> userGroupsDNs = getUserGroupsDNs(userId);
		Set<Group> groups = new HashSet<>();
		for (String dn : facilityGroupsDNs) {
			if (userGroupsDNs.contains(dn)) {
				Group group = ldap.lookup(ldap.newDn(dn), new String[]{PERUN_GROUP_ID, PERUN_UNIQUE_GROUP_NAME, CN, DESCRIPTION}, e -> {
					Attribute parentGid = e.get(PERUN_PARENT_GROUP_ID);
					return new Group(
							Long.parseLong(e.get(PERUN_GROUP_ID).getString()),
							parentGid != null ? Long.parseLong(parentGid.get().getValue()) : null,
							e.get(CN).getString(),
							e.get(DESCRIPTION).getString(),
							e.get(PERUN_UNIQUE_GROUP_NAME).getString()
					);
				});
				log.trace("facility={},user={} - group {} matches", facility.getId(), userId, group);
				groups.add(group);
			}
		}
		return groups;
	}

	/**
	 * Gets DNs of all groups of a user.
	 */
	private Set<String> getUserGroupsDNs(Long userId) {
		String userDN = PERUN_USER_ID + "=" + userId + ",ou=People," + baseDN;
		return new HashSet<>(ldap.lookup(ldap.newDn(userDN), new String[]{MEMBER_OF}, e -> getAttributeValues(e, MEMBER_OF)));
	}

	/**
	 * Gets DNs of all groups assigned to all resources of the facility.
	 */
	private Set<String> getFacilityGroupsDNs(Facility facility) {
		FilterBuilder filter = and(equal(OBJECT_CLASS, PERUN_RESOURCE), equal(PERUN_FACILITY_ID, Long.toString(facility.getId())));
		Set<String> groupDNs = new HashSet<>();
		ldap.search(ldap.newDn(baseDN), filter, SearchScope.SUBTREE,
				new String[]{PERUN_VO_ID, ASSIGNED_GROUP_ID}, e ->
				{
					String voId = e.get(PERUN_VO_ID).getString();
					for (String groupId : getAttributeValues(e, ASSIGNED_GROUP_ID)) {
						groupDNs.add(PERUN_GROUP_ID + "=" + groupId + "," + PERUN_VO_ID + "=" + voId + "," + baseDN);
					}
					return null;
				}
		);
		return groupDNs;
	}

	/**
	 * Gets all String values of an attribute from a LDAP entry.
	 */
	private static List<String> getAttributeValues(Entry e, String attributeName) {
		return StreamSupport.stream(e.get(attributeName).spliterator(), false).map(Value::getValue).collect(Collectors.toList());
	}
}