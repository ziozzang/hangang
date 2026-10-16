// Identities section router (ADR 0020 §3). Routes:
//   #identities[/users][?q=&status=&group=]   users list
//   #identities/users/{id}[/{tab}]            user detail
//   #identities/sessions[?user=]              live sessions
//   #identities/groups[?q=&source=] , /{id}   groups and group detail
//   #identities/providers                     identity providers
//   #identities/authentication[/test]         profiles editor, access test
//   #identities/projections                   credential projections
import { renderUsers } from './users.js';
import { renderUser } from './user.js';
import { renderSessions } from './sessions.js';
import { renderGroups, renderGroup } from './groups.js';
import { renderProviders } from './providers.js';
import { renderAuthentication } from './authentication.js';
import { renderProjections } from './projections.js';

export async function renderIdentities(cx, root, route) {
  const [page, id, tab] = route.parts;
  if (page === 'users' && id) return renderUser(cx, root, id, tab);
  if (page === 'sessions') return renderSessions(cx, root, route.params);
  if (page === 'groups' && id) return renderGroup(cx, root, id);
  if (page === 'groups') return renderGroups(cx, root, route.params);
  if (page === 'providers') return renderProviders(cx, root);
  if (page === 'authentication') return renderAuthentication(cx, root, route.parts.slice(1), route.params);
  if (page === 'projections') return renderProjections(cx, root);
  return renderUsers(cx, root, route.params);
}
