import com.google.common.collect.Sets
import groovy.json.JsonSlurper
import org.sonatype.nexus.security.role.NoSuchRoleException
import org.sonatype.nexus.security.role.Role
import org.sonatype.nexus.security.role.RoleIdentifier
import org.sonatype.nexus.security.user.UserManager

import static com.google.common.base.Preconditions.checkNotNull

def jsonSlurper = new JsonSlurper()

def authorizationManager = security.securitySystem
        .getAuthorizationManager(UserManager.DEFAULT_SOURCE)

jsonSlurper.parseText(new File("/home/nexus/roles.json").text).each { parsedRole ->
    if (parsedRole.source != UserManager.DEFAULT_SOURCE) {
        return
    }
    if (parsedRole.readOnly){
        return 
    }

    def roleName = parsedRole.name != null ? parsedRole.name : parsedRole.roleId
    try {
        def role = authorizationManager.getRole(parsedRole.roleId)
        role.name = roleName
        role.description = parsedRole.description
        role.privileges = Sets.<String> newHashSet(checkNotNull(parsedRole.privileges))
        role.roles = Sets.<String> newHashSet(checkNotNull(parsedRole.roles))
        authorizationManager.updateRole(role)
    } catch (NoSuchRoleException ignored) {
        authorizationManager.addRole(new Role(
                roleId: checkNotNull(parsedRole.roleId),
                source: parsedRole.source,
                name: roleName,
                description: parsedRole.description,
                privileges: Sets.<String> newHashSet(checkNotNull(parsedRole.privileges)),
                roles: Sets.<String> newHashSet(checkNotNull(parsedRole.roles))
        ))
    }
}

jsonSlurper.parseText(new File("/home/nexus/users.json").text).each { parsedUser ->
    def roleIdentifiers = new HashSet()
    parsedUser.roles.each { role -> roleIdentifiers.add(new RoleIdentifier(role.source, role.roleId)) }
    security.securitySystem.setUsersRoles(parsedUser.userId, parsedUser.source, roleIdentifiers)
}