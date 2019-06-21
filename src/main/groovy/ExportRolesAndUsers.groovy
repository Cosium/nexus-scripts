import groovy.json.JsonOutput

def roles = security.securitySystem.listRoles()
new File('/home/nexus/roles.json').write(JsonOutput.prettyPrint(JsonOutput.toJson(roles)))

def users = security.securitySystem.listUsers()
new File('/home/nexus/users.json').write(JsonOutput.prettyPrint(JsonOutput.toJson(users)))