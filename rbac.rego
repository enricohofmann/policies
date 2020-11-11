package rbac.authz

# user-role assignments
user_roles := {
    "bonnie": ["schueler"],
    "clara": ["putzfrau"]
}

# role-permissions assignments
role_permissions := {
    "schueler": [{"resource": "toilette", "action": "benutzen"}],
    "putzfrau": [
        {"resource": "toilette", "action": "benutzen"}, 
        {"resource": "toilette", "action": "putzen"}
        ],
}

allow {
    roles := user_roles[input.user]
    r := roles[_]
    permissions := role_permissions[r]
    p := permissions[_]
    p == {"resource": input.resource, "action": input.action}
}