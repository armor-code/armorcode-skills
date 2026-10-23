# Access control: teams, users, roles, API keys

Changes here decide who can see and change what. Every write in this file is **HIGH** risk, so show the user exactly who gains or loses access before applying.

## Contents
1. How access works
2. Teams
3. Users
4. Roles and permissions
5. API keys
6. Recipes

---

## 1. How access works

- A user has either a **tenant role** (organization-wide: Account Admin, Read Only and so on) or **team memberships**. In each team the user holds a role chosen for that team, so one person can be a Developer on one team and Read Only on another.
- A team's **access scope** is a list of hierarchy paths, groups/subgroups, or "all groups" (`properties[]`). Path rules are in `org-model.md` §3: a bare path covers one node, `path/.*` covers its subtree, and matching is lowercase and case-sensitive.
- A group's **assigned team** (`teamDto` on the group) is separate from access scope. It's the team shown on the group, and its members are the candidates for the group's owner slots.
- Permissions are enforced per route: each role grants permission sub-categories such as `CREATE_PRODUCT`, and a route the role doesn't grant returns 403. **Account Admin** skips these checks.

## 2. Teams

| Need | Command / endpoint |
|---|---|
| List | `ac.py teams`: `GET /api/team/all-teams` |
| Detail (members, scope) | `ac.py team ID`: `GET /api/team/{id}`. Members: `{id, role:{id,name}, user:{id,name=email}, disableLogin}`. Scope: `properties[{businessUnit, groups, productSubProductMap, accessOnAllProduct}]` |
| Search with members and scope | `ac.py query /api/team/filtered-data -p page=0 -p size=100 --body '{}'` |
| Add or remove members | `ac.py plan team-members ID --add USER_ID:ROLE_NAME --remove USER_ID_OR_EMAIL` |
| Create | `ac.py plan raw POST /api/team --body @team.json` (permission `CREATE_TEAM`) |
| Delete | `ac.py plan raw DELETE /api/team/ID` (CRITICAL; `DELETE_TEAM`) |

Create body (scope by hierarchy path):
```json
{"name": "Payments Engineering", "description": "…",
 "members": [{"user": {"id": 123}, "role": "Developer"}],
 "properties": [{"businessUnitId": 1234, "businessUnitName": "Acme",
                 "productSubProductMap": [], "accessOnAllProduct": false,
                 "groups": ["acme/payments/.*"]}]}
```

Behaviors that cause damage, all handled by `plan team-members`:
- **The member list is replaced wholesale.** Sending 29 of 30 members removes one; sending none removes everyone. The helper re-reads the team at apply time and merges your change into the current list.
- **Use `PUT /api/team/with-user` for membership changes.** `PUT /api/team` doesn't reliably apply member changes, even though it returns 200. The helper uses `with-user`, which can't change the caller's own membership.
- **Team writes re-enable login.** After a team update, every listed member can log in, including members whose login was disabled. The helper refuses when a current member has login disabled, unless `--accept-login-reset` is given. In that case, tell the user to disable those logins again afterwards (`PUT /user/update/user`).
- **The access scope must survive.** The helper converts the GET record into the PUT shape and checks afterwards that the scope is unchanged.
- **Delete only an empty team.** A DELETE on a team that still has members can return 200 while removing only the members. Remove the members first. `apply` verifies the team is gone.

## 3. Users

| Need | Command / endpoint |
|---|---|
| Search | `ac.py users [--email x] [--name y]`: `POST /api/v2/user/search`, page/size as query params. The body takes top-level lists such as `{"searchEmail":["jdoe"]}`, `{"searchText":["jdoe"]}` or `{"email":["a@b.com"]}`. A `filters` wrapper is ignored and returns everyone. Results are under `data.content`; ids are `userId` |
| Create | `plan raw POST /user/add/user` with `{email, name, teamInfo:[{teamId, teamName, role}]}` **or** `{email, tenantRole}`, plus `disableLogin` (permission `CREATE_USER`) |
| Update | `plan raw PUT /user/update/user` with `{id, …}` (`UPDATE_USER`; you can't change your own role, and only Account Admins can update Account Admins) |
| Remove | `plan raw DELETE /user/data/remove/{userId}` (CRITICAL; `DELETE_USER`). The user's API keys stop working. You can't remove yourself |

- Per ArmorCode's docs, user add and remove need an **Account Admin** API key. Across organizations the key also needs **Account Level Access**.
- You can't grant a role above your own.
- With SSO/SCIM, user lifecycle usually belongs to the identity provider. Ask before creating users by API.

## 4. Roles and permissions

| Need | Endpoint |
|---|---|
| List roles | `ac.py roles`: `GET /user/roles` (`outOfBox` roles can't be edited) |
| A role's permissions | `ac.py get /user/businessunit/role/permissions -p role=<name>` |
| Create a role | `plan raw POST /admin/user/role` with `{role, description (required), existingRole: <roleId to copy>, defaultDashboard}` (`CREATE_ROLE`) |
| Set its permissions | `plan raw POST /admin/user/map/role/permission` with `{roleId, subCategory:[…]}`. This **replaces** the set; out-of-box roles are rejected (`UPDATE_ROLE`) |

- Role names allow letters, digits, spaces, `_` and `-`, and can't start or end with a space, `_` or `-`. Parentheses fail.
- To build a least-privilege role for this skill:
  1. Copy *Read Only* (`existingRole`).
  2. Add only the needed sub-categories, e.g. `UPDATE_PRODUCT`, `CREATE_SUB_PRODUCT`, `UPDATE_SUB_PRODUCT` for hierarchy work.
  3. Read the result back and diff it against what you intended. The map call doesn't report partial application.
- The permission catalog differs by tenant and version. Build it as the union of every role's permissions; Account Admin holds all of them.

Permission names for common writes:

| Write | Permission |
|---|---|
| Create / update / delete group | `CREATE_PRODUCT` / `UPDATE_PRODUCT` / `DELETE_PRODUCT` |
| Create subgroup, bulk move, version | `CREATE_SUB_PRODUCT` |
| Update subgroup, mass tag | `UPDATE_SUB_PRODUCT` |
| Delete subgroup | `DELETE_SUB_PRODUCT` |
| Teams | `CREATE_TEAM` / `UPDATE_TEAM` / `DELETE_TEAM` |
| Users | `CREATE_USER` / `UPDATE_USER` / `DELETE_USER` |
| Roles | `CREATE_ROLE` / `UPDATE_ROLE` |
| Scan upload, tool mappings | `CREATE_TOOLS` / `UPDATE_TOOLS` / `DELETE_TOOLS` |
| Repo mapping | `UPDATE_TOOLS` |
| Ticket mapping create | `CREATE_TICKETS` |

## 5. API keys

How to create keys and choose types and scopes is in `setup.md`. Through the API (Internal):
- `POST /user/apikey` with `{name (3–50), apiTokenType: USER|APP_SEC_TOOL|CICD_TOOL|…, role: <roleId, USER only>, expiry, accountLevelToken | scopeType + productIds/armorcodeGroups}`. The response contains the new key **once**.
  - Never print it. Write it straight into the user's secret store, or better, have the user create keys in the UI.
- `PUT /user/apikey/{id}` needs `CREATE_TOOLS`; `DELETE /user/apikey/{id}` needs `DELETE_TOOLS`.
- Keys stop working when their creator is removed. Plan rotation before offboarding automation owners.

## 6. Recipes

### Who can see this group?
1. `ac.py group ID` gives its hierarchy paths and assigned team.
2. `ac.py query /api/team/filtered-data -p page=0 -p size=200 --body '{}' --out teams.json`. Find teams whose `groups` entries match the paths: bare equals the node; `x/.*` covers the subtree. Also check teams that pick the group directly in `productSubProductMap` or have `accessOnAllProduct`.
3. Add tenant-role users from `ac.py users`, since they see everything in scope of their role.

### Give a new engineer access
1. `ac.py users --email person@company.com`. If the user doesn't exist and SSO isn't managing users, plan the create with a team assignment.
2. `ac.py plan team-members TEAM_ID --add USER_ID:Developer`, then review and apply.

### Offboard someone
1. Remove them from teams (`plan team-members --remove`), or remove the user (CRITICAL).
2. Check whether they owned API keys used by integrations. Those keys stop working when the user is removed.
3. Check owner slots on groups (`ac.py group ID`) and reassign them with `plan group-update --owner securityOwner=NEW_ID`.
