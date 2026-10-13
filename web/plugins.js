// Host console lifecycle for trusted, hash-pinned operator-installed modules.
let catalog = [], mounted = new Map(), generation = 0, host;
export function pluginView(name) { return catalog.some(p => name === 'plugin-' + p.id); }
export async function discoverPlugins(context) {
  resetPlugins(); host = context; const epoch = generation;
  const { data } = await context.api('/v1/plugins');
  if (epoch !== generation) return;
  if (data?.api_version !== 1 || !Array.isArray(data.plugins)) throw Error('Unsupported console plugin contract');
  const navigation=document.querySelector('.sidebar nav');
  const anchor=navigation.querySelector('[data-i18n="MANAGE"]');
  for (const p of data.plugins) {
    if (!/^[a-z0-9-]{1,32}$/.test(p.id) || typeof p.name !== 'string' || !p.entry?.startsWith(`/ui/plugins/${p.id}/`) || p.api_base !== `/v1/plugins/${p.id}`) throw Error('Invalid console plugin discovery');
    const name='plugin-'+p.id;
    const link=document.createElement('a');link.className='nav-link';link.dataset.view=name;link.dataset.adminOnly='';link.href='#'+name;link.dataset.consolePlugin=p.id;
    const icon=document.createElement('span');icon.setAttribute('aria-hidden','true');icon.textContent='◇';const label=document.createElement('bdi');label.textContent=p.name;link.append(icon,label);
    navigation.insertBefore(link,anchor);
    const section=document.createElement('section');section.id='view-'+name;section.className='view';section.hidden=true;section.dataset.consolePlugin=p.id;
    const head=document.createElement('div');head.className='page-head';const title=document.createElement('h1');title.textContent=p.name;head.append(title);const root=document.createElement('div');root.className='plugin-root';section.append(head,root);document.querySelector('#main').append(section);
    catalog.push({...p,name,root});
  }
}
export function pausePlugins() { for(const m of mounted.values()){m.paused=true;m.instance?.pause?.();} }
export async function loadPlugin(name) {
  const p=catalog.find(p=>p.name===name);if(!p)throw Error('Unknown console plugin');
  if(mounted.has(name)){const record=mounted.get(name);record.paused=false;record.instance?.resume?.();return;}
  const epoch=generation, controller=new AbortController(), record={controller,instance:null,paused:false};mounted.set(name,record);
  const base=p.entry.slice(0,p.entry.lastIndexOf('/')+1);
  const style=document.createElement('link');style.rel='stylesheet';style.href=base+'style.css';style.dataset.consolePlugin=p.id;document.head.append(style);
  try {
    const module=await import(p.entry);
    if(epoch!==generation || controller.signal.aborted)return;
    if(typeof module.mount!=='function')throw Error('Console plugin has no mount function');
    record.instance=await module.mount(Object.freeze({root:p.root,signal:controller.signal,locale:host.locale,authentication:p.authentication==='hangang'?'hangang':'native',
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
