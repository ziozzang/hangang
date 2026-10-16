// Network section router (ADR 0020 §5). Routes:
//   #network[/overview]                 overview
//   #network/threats?q=&stage=&asn=&eligible=   threat queue
//   #network/ip/{ip}                    IP detail
//   #network/blocks[/allowlist]         blocks and allowlist
//   #network/rules[/lua]?rule=          rules editor
//   #network/policy                     mode, weights and thresholds
//   #network/zones[/{id}]               network zones
//   #network/asn                        ASN pools
import { renderNetworkOverview } from './overview.js';
import { renderThreats } from './threats.js';
import { renderIpDetail } from './ip.js';
import { renderBlocks } from './blocks.js';
import { renderRules } from './rules.js';
import { renderPolicy } from './policy.js';
import { renderAsn } from './asn.js';
import { renderZones } from './zones.js';

export async function renderNetwork(cx, root, route) {
  const [page, id] = route.parts;
  if (page === 'ip' && id) return renderIpDetail(cx, root, id);
  if (page === 'threats') return renderThreats(cx, root, route.params);
  if (page === 'blocks') return renderBlocks(cx, root, route.parts.slice(1), route.params);
  if (page === 'rules') return renderRules(cx, root, route.parts.slice(1), route.params);
  if (page === 'policy') return renderPolicy(cx, root);
  if (page === 'zones') return renderZones(cx, root, route.parts.slice(1));
  if (page === 'asn') return renderAsn(cx, root, route.params);
  return renderNetworkOverview(cx, root);
}
