package cz.muni.ics.oidc.server.connectors;

import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.Group;
import cz.muni.ics.oidc.models.PerunAttribute;
import cz.muni.ics.oidc.models.PerunUser;
import cz.muni.ics.oidc.models.RichUser;
import cz.muni.ics.oidc.models.Vo;
import cz.muni.ics.oidc.server.PerunPrincipal;

import java.util.List;
import java.util.Map;

/**
 * Connects to Perun and obtains information.
 * Used for fetching necessary data about users, services etc.
 *
 * @author Martin Kuba makub@ics.muni.czc
 * @author Dominik František Bučík bucik@ics.muni.cz
 * @author Peter Jancus jancus@ics.muni.cz
 */
public interface PerunConnector {

	/**
	 * Fetch user based on his principal (extLogin and extSource) from Perun
	 *
	 * @param perunPrincipal principal of user
	 * @return PerunUser with id of found user
	 */
	PerunUser getPreauthenticatedUserId(PerunPrincipal perunPrincipal);

	/**
	 * Fetch user identified by userId from Perun with all attributes.
	 *
	 * @param userId identifier of the user
	 * @return RichUser with attributes of found user
	 */
	RichUser getUserAttributes(Long userId);

	/**
	 * Fetch facility registered in Perun for the given OIDC client_id.
	 *
	 * @param clientId value for attribute OIDCClientID
	 * @return facility if it was found or null
	 */
	Facility getFacilityByClientId(String clientId);

	/**
	 * Ask Perun if user's access to the facility should be checked.
	 *
	 * @param facility facility to be accessed
	 * @return TRUE if check should be done, FALSE otherwise
	 */
	boolean isMembershipCheckEnabledOnFacility(Facility facility);

	/**
	 * Perform check if user can access service based on his/her membership
	 * in groups assigned to facility resources
	 *
	 * @param facility facility to be accessed
	 * @param userId id of user to check
	 * @return true if user can access, false otherwise
	 */
	boolean canUserAccessBasedOnMembership(Facility facility, Long userId);

	/**
	 * Get list of groups where user can register to gain access to the service
	 *
	 * @param facility facility the user tries to access
	 * @param userId id of user
	 * @return List of groups where user can register or empty list
	 */
	Map<Vo, List<Group>> getGroupsForRegistration(Facility facility, Long userId, List<String> voShortNames);

	/**
	 * Decide if there is a group where user can register
	 *
	 * @param facility facility being accessed
	 * @return true if at least one group with registration form exists
	 */
	boolean groupWhereCanRegisterExists(Facility facility);

	/**
	 * Get specified attributes for facility.
	 *
	 * @param facility facility having requested attributes
	 * @param attributeNames attributes to be fetched
	 * @return Map in format attribute URN, attribute
	 */
	Map<String, PerunAttribute> getFacilityAttributes(Facility facility, List<String> attributeNames);

	/**
	 * Gets user membership in group.
	 * @param userId id of user
	 * @param groupId id of group
	 * @return true if the user is member of the group
	 */
	boolean isUserInGroup(Long userId,Long groupId);

	/**
	 * Gets the attribute of the user.
	 * @param userId id of user
	 * @param attributeName full name of attribute
	 * @return attribute
	 */
	PerunAttribute getUserAttribute(Long userId, String attributeName);

	/**
	 * For the given user, gets all string values of the affiliation attribute of all UserExtSources of type ExtSourceIdp
	 * @param userId id of user
	 * @return list of values of attribute affiliation
	 */
	List<Affiliation> getUserExtSourcesAffiliations(Long userId);

	/**
	 * For the given user, gets all string values of the groupAffiliation attribute of groups of the user
	 * @param userId id of user
	 * @return list of values of attribute affiliation
	 */
	List<Affiliation> getGroupAffiliations(Long userId);

	/**
	 * Gets the entityless attribute.
	 * @param attributeName full name of attribute
	 * @return attribute
	 */
	PerunAttribute getEntitylessAttribute(String attributeName);

	/**
	 * Gets the VO attribute
	 * @param voId Id of VO
	 * @param attributeName fullname of attribute
	 * @return Attribute
	 */
	PerunAttribute getVoAttribute(Long voId, String attributeName);

	/**
	 * Returns the VO with shortName
	 * @param shortName shortname of VO
	 * @return Vo
	 */
	Vo getVoByShortName(String shortName);
}
