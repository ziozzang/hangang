// Fixed fixture credential slots; no caller-provided header names or raw headers.
export function applicationAuthorization(application){
  const scheme=application.credentialScheme??'bearer';
  if(!['bearer','hopae_compose'].includes(scheme))throw new Error('unsupported application credential scheme');
  if(typeof application.key!=='string'||!(/^[\x21-\x7e]{1,4096}$/).test(application.key))throw new Error('invalid application credential payload');
  return (scheme==='bearer'?'Bearer ':'Hopae-Compose ')+application.key;
}
export function redact(message,secrets){
  const values=secrets.filter(value=>typeof value==='string'&&value.length).sort((a,b)=>b.length-a.length);
  for(const value of values)message=message.replaceAll(value,'[redacted]');
  return message;
}
