import { t } from './i18n.js';
import { ui } from './kit/ui.js';
import { t as kitT } from './zt/shell.js';
// Host console lifecycle for trusted, hash-pinned operator-installed modules.
let catalog = [], mounted = new Map(), generation = 0, host;
const authorities = Object.freeze({ hopae: { label: 'Identity · Hopae', aliases: 'identity authentication 호패 신원 인증', order: 0 }, guard: { label: 'Network trust · Sumunjang', aliases: 'guard network trust 수문장 네트워크 신뢰', order: 1 } });
export const SUPERSEDED = Object.freeze({ guard: '#network' });
const authorityFor = id => Object.hasOwn(authorities, id) ? authorities[id] : undefined;
export function pluginView(name) { return catalog.some(p => name === 'plugin-' + p.id); }
export async function discoverPlugins(context) {
  resetPlugins(); host = context; const epoch = generation;
  const { data } = await context.api('/v1/plugins');
  if (epoch !== generation) return;
  if (data?.api_version !== 1 || !Array.isArray(data.plugins)) throw Error('Unsupported console plugin contract');
  const navigation=document.querySelector('.sidebar nav');
  const anchor=navigation.querySelector('[data-nav-slot="zero-trust-end"]');
  const ids = new Set();
  // Validate the entire discovery before creating any executable/navigation state.
  if (data.plugins.length > 128) throw Error('Invalid console plugin discovery');
  for (const p of data.plugins) {
    if (!p || typeof p.id !== 'string' || ids.has(p.id)) throw Error('Invalid console plugin discovery');
    ids.add(p.id);
    if (!/^[a-z0-9-]{1,32}$/.test(p.id) || typeof p.name !== 'string' || typeof p.entry !== 'string' || !p.entry.startsWith(`/ui/plugins/${p.id}/`) || p.api_base !== `/v1/plugins/${p.id}`) throw Error('Invalid console plugin discovery');
  }
  // Packages superseded by Zero Trust task sections keep their broker routes but no page (ADR 0020).
  const sorted = [...data.plugins].filter(p => !Object.hasOwn(SUPERSEDED, p.id)).sort((a,b) => (authorityFor(a.id)?.order ?? 3) - (authorityFor(b.id)?.order ?? 3) || a.id.localeCompare(b.id, 'en'));
  for (const p of sorted) {
    const name='plugin-'+p.id;
    const link=document.createElement('a');link.className='nav-link';link.dataset.view=name;link.dataset.adminOnly='';link.href='#'+name;link.dataset.consolePlugin=p.id;
    const icon=document.createElement('span');icon.setAttribute('aria-hidden','true');icon.textContent='◇';const label=document.createElement('bdi');const authority=authorityFor(p.id);label.textContent=authority ? t(authority.label) : p.name;if(authority)label.dataset.i18n=authority.label;link.dataset.searchAliases=authority?.aliases || p.id;link.append(icon,label);
    navigation.insertBefore(link, anchor);
    const section=document.createElement('section');section.id='view-'+name;section.className='view';section.hidden=true;section.dataset.consolePlugin=p.id;
    const head=document.createElement('div');head.className='page-head';const title=document.createElement('h1');title.id='plugin-'+p.id+'-title';title.textContent=authority ? t(authority.label) : p.name;if(authority)title.dataset.i18n=authority.label;section.setAttribute('aria-labelledby',title.id);head.append(title);const root=document.createElement('div');root.className='plugin-root';section.append(head,root);document.querySelector('#main').insertBefore(section,document.querySelector('#geoip-attribution'));
    catalog.push({...p,name,root});
  }
}
export function pausePlugins() { for(const m of mounted.values()){m.paused=true;m.instance?.pause?.();} }
export async function loadPlugin(name) {
  const p=catalog.find(p=>p.name===name);if(!p)throw Error('Unknown console plugin');
  if(mounted.has(name)){const record=mounted.get(name);record.paused=false;record.instance?.resume?.();return;}
  const epoch=generation, controller=new AbortController(), record={controller,instance:null,paused:false,localeListeners:new Set()};mounted.set(name,record);
  controller.signal.addEventListener('abort',()=>record.localeListeners.clear(),{once:true});
  const base=p.entry.slice(0,p.entry.lastIndexOf('/')+1);
  const style=document.createElement('link');style.rel='stylesheet';style.href=base+'style.css';style.dataset.consolePlugin=p.id;document.head.append(style);
  try {
    const module=await import(p.entry);
    if(epoch!==generation || controller.signal.aborted)return;
    if(typeof module.mount!=='function')throw Error('Console plugin has no mount function');
    record.instance=await module.mount(Object.freeze({root:p.root,signal:controller.signal,locale:host.locale,onLocaleChange:(listener)=>{
        if(typeof listener!=='function')throw Error('Invalid locale listener');
        if(controller.signal.aborted)return ()=>{};
        if(record.localeListeners.size>=8)throw Error('Too many locale listeners');
        const notify=()=>{if(epoch===generation&&!controller.signal.aborted)listener(host.locale());};
        record.localeListeners.add(notify);
        window.addEventListener('hangang:localechange',notify,{signal:controller.signal});
        return ()=>{record.localeListeners.delete(notify);window.removeEventListener('hangang:localechange',notify);};
      },authentication:p.authentication==='hangang'?'hangang':'native',
      // Shared UI kit (ADR 0020). Additive: v1 packages that ignore it are unaffected.
      ui,t:kitT,navigate:(hash)=>{if(typeof hash==='string'&&/^#[a-z0-9-]+(?:[/?][^\s]*)?$/i.test(hash))location.hash=hash;},link:(entity)=>ui.entityHref(entity?.type,entity?.id),
      api:(path,options={})=>{if(controller.signal.aborted) return Promise.reject(Error('Session ended'));if(!/^[a-z0-9-]+(?:\/[a-z0-9-]+)*$/.test(path))return Promise.reject(Error('Invalid plugin API path'));return host.api(p.api_base+'/'+path,{...options,signal:controller.signal});},
      asset:(file)=>{if(!/^[a-zA-Z0-9_-]+\.(html|css)$/.test(file))return Promise.reject(Error('Invalid plugin asset'));return fetch(base+file,{signal:controller.signal,cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Plugin asset unavailable');return r;});}
    }));
    if(epoch!==generation || controller.signal.aborted){record.instance?.dispose?.();return;}
    if(record.paused)record.instance?.pause?.();
  } catch(error) {if(mounted.get(name)===record)mounted.delete(name);controller.abort();style.remove();p.root.replaceChildren();if(epoch===generation)throw error;}
}
export function resetPlugins() {
  generation++;for(const {controller,instance} of mounted.values()){controller.abort();instance?.dispose?.();}mounted.clear();catalog=[];
  document.querySelectorAll('[data-console-plugin]').forEach(el=>el.remove());host=null;
}
