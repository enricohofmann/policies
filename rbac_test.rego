package rbac.authz

test_bonnie{
    allow with input as {"user": "bonnie", "resource": "toilette", "action": "benutzen"}
    not allow with input as {"user": "bonnie", "resource": "toilette", "action": "putzen"}
}

test_clara{
    allow with input as {"user": "clara", "resource": "toilette", "action": "benutzen"}
    allow with input as {"user": "clara", "resource": "toilette", "action": "putzen"}
}