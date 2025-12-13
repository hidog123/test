# opa/policy.rego

package authz

default allow = false

# Règle principale : Autoriser si un des critères est vrai
allow {
    has_zt_user_role
}

# Règle optionnelle basée sur le contexte (ex: IP locale)
allow {
    is_local_ip
}

# Vérifie si l'utilisateur a le rôle 'zt-user'
has_zt_user_role {
    # 'input' est le corps de la requête envoyée par Traefik (ForwardAuth)
    some i
    # Les rôles sont généralement dans le jeton JWT (Ticket)
    # L'exemple Traefik ForwardAuth envoie les rôles dans un header
    input.headers["X-Forwarded-User-Roles"][i] == "zt-user"
}

# Vérifie si la requête provient d'une IP "interne"
is_local_ip {
    input.headers["X-Forwarded-For"] == "172.18.0.1" # Exemple d'IP interne du réseau Docker
}

# Si le déni est décidé, nous retournons un statut d'erreur
# Le statut par défaut est 403, mais on peut le personnaliser
deny[msg] {
    not allow
    msg := "Access Denied by Zero Trust Policy (OPA)"
}
