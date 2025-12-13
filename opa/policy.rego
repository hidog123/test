# opa/policy.rego (Politique Zero Trust basée sur Traefik/Keycloak)

package authz

import future.keywords.if

default allow = false

# L'utilisateur "alice" doit avoir le rôle 'zt-user' pour réussir le jugement ZT.
# L'utilisateur "bob" n'a que le rôle 'guest' et sera refusé.

# Définir les rôles requis pour l'accès à la demo-app
required_roles := {"zt-user"}

# Définir les rôles de l'utilisateur (extraits de l'en-tête envoyé par ForwardAuth)
user_roles := input.headers["X-Forwarded-User-Roles"]

# Règle d'autorisation (Judgement: OUI)
allow if {
    # 1. CONTEXTE : La méthode HTTP est "GET"
    input.method == "GET"
    
    # 2. IDENTITÉ/TICKET : L'un des rôles de l'utilisateur est dans les rôles requis
    user_roles_intersection := required_roles & user_roles
    count(user_roles_intersection) > 0
}

# Règle d'autorisation alternative (pour le debug/test d'IP interne)
allow if {
    # 3. CONTEXTE : L'IP de la requête est une IP de "confiance" (simulant un accès VPN/réseau local)
    input.headers["X-Forwarded-For"] == "172.18.0.1"
}


# Règle de déni (si aucune règle "allow" n'est satisfaite)
deny[msg] if {
    not allow
    msg := "Access Denied by Zero Trust Policy. Required role: zt-user"
}
