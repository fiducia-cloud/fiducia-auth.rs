#!/usr/bin/env node
// Independent, dependency-free finite-state oracle. It does not execute production code.
// Model bound and the required implementation refinement are documented in formal/README.md.
function fiducia_auth_model() {
  const ok=(x,m)=>{if(!x)throw Error(m)};
  const init = presentedGen=>({now:0,activeGen:1,presentedGen,revoked:false,
    cacheGen:0,cacheUntil:0,cacheAllow:false});
  const cacheAllowed=s=>s.cacheAllow&&s.cacheGen===s.presentedGen&&s.now<s.cacheUntil;
  const freshAllowed=s=>!s.revoked&&s.activeGen===s.presentedGen;
  const invariant=s=>s.now>=0&&s.now<=3&&s.activeGen>=1&&s.activeGen<=2&&
    s.cacheUntil<=4 && (!s.cacheAllow || s.cacheGen>0);
  let states=0,edges=0,cacheGrants=0,expiredDenials=0,rotations=0,revocations=0,renewals=0;
  for(const gen of [1,2]) {
    const start=init(gen),q=[start],seen=new Set([JSON.stringify(start)]);
    for(let i=0;i<q.length;i++){
      const s=q[i];ok(invariant(s),"invalid revocation state");
      const next=[];
      if(s.now<3)next.push(["tick",{...s,now:s.now+1}]);
      if(s.activeGen===1)next.push(["rotate",{...s,activeGen:2}]);
      if(!s.revoked)next.push(["revoke",{...s,revoked:true}]);
      if(freshAllowed(s))next.push(["introspect_valid",{...s,cacheGen:gen,cacheUntil:s.now+1,cacheAllow:true}]);
      if(cacheAllowed(s)){cacheGrants++;ok(s.now<s.cacheUntil,"expired cache grant");}
      else if(s.cacheAllow && s.cacheGen===gen && s.now>=s.cacheUntil) expiredDenials++;
      if(s.revoked&&s.now>=s.cacheUntil)ok(!cacheAllowed(s)&&!freshAllowed(s),"post-TTL revoke bypass");
      if(s.activeGen!==gen)ok(!freshAllowed(s),"old generation allowed fresh access");
      for(const [name,n] of next){
        ok(invariant(n),`bad ${name}`);
        if(name==="introspect_valid")ok(!s.revoked&&s.activeGen===gen,"revoked key renewed");
        edges++;const k=JSON.stringify(n);if(!seen.has(k)){seen.add(k);q.push(n);}
      }
    }
    states+=q.length;
  }
  ok(states>=25&&cacheGrants>0&&expiredDenials>0,"vacuous key lifecycle");
  ok(!cacheAllowed({...init(1),cacheAllow:true,cacheGen:1,cacheUntil:1,now:1}),"expired cache mutant survived");
  ok(!freshAllowed({...init(1),revoked:true}),"revoked key mutant survived");
  return {model:"Fiducia API-key rotation/revocation cache TTL",states,edges,cacheGrants,expiredDenials,scope:"two key generations, three clock ticks, TTL one tick"};
}
console.log(JSON.stringify(fiducia_auth_model()));
