"use strict";(globalThis.webpackChunk=globalThis.webpackChunk||[]).push([["app_assets_modules_blackbird-monolith_hooks_use-navigate-to-query_ts-app_assets_modules_black-182e14","app_components_search_parsing_parsing_ts"],{93756:(e,t,n)=>{n.d(t,{D_:()=>p,Yl:()=>f,or:()=>u,zk:()=>d});var r=n(10866),o=n(96974),i=n(29456),s=n(67294),a=n(90409),c=n(91691),l=n(54529);function u(e){return e.ctrlKey||e.metaKey||1===e.button}function d(){let e=(0,a.z)(r.gx),t=(0,o.TH)();return(0,s.useCallback)(async(n,o,s,a)=>{let{newQuery:c,newSearchParams:l}=h(t,n,o,s);(0,i.rE)(c),a?window.open((0,r.Gr)(r.gx,void 0,{...l,q:c}).href,"_blank"):e(void 0,{...l,q:c})},[e,t])}function f(){let e=(0,o.TH)();return(0,s.useCallback)((t,n,o)=>{let{newQuery:i,newSearchParams:s}=h(e,t,n,o);return(0,r.Gr)(r.gx,void 0,{...s,q:i}).href},[e])}function p(e){let t;try{t=JSON.parse(e||"[]"),Array.isArray(t)||(t=[])}catch(e){t=[]}return t}function h(e,t,n,r){let o=new URLSearchParams(e.search),i=t??o.get("q")??"";n&&(i=i?`${i} ${n}`:n);let s=r||{},a=(0,l.Z)().join(",");""!==a?s.experiments=a:s.experiments=null;let u=o.get("saved_searches");if(u){let e=p(u);if(e.length>0){let t=(0,c.parseString)(i);s.expanded_query=(0,c.getExpandedQuery)(i,e,t)}}return{newQuery:i,newSearchParams:s}}},29456:(e,t,n)=>{n.d(t,{No:()=>f,nt:()=>d,rE:()=>u,rS:()=>l});var r=n(67294),o=n(93756),i=n(96974);let s="blackbird_monolith_retransmit_react",a="blackbird_monolith_search",c="blackbird_monolith_set_global_nav_visibility";function l(){(0,r.useEffect)(()=>{function e(){window.dispatchEvent(new CustomEvent("blackbird_monolith_react_connected")),window.dispatchEvent(new CustomEvent(c,{detail:!1}))}return e(),window.addEventListener(s,e),()=>{window.dispatchEvent(new CustomEvent(c,{detail:!0})),window.removeEventListener(s,e),window.dispatchEvent(new CustomEvent("blackbird_monolith_react_disconnected"))}},[]);let e=(0,o.zk)();(0,r.useEffect)(()=>{function t(t){t instanceof CustomEvent&&e(t.detail.search,void 0,t.detail.searchParams)}return window.addEventListener(a,t),()=>{window.removeEventListener(a,t)}},[e]);let{search:t}=(0,i.TH)(),n=new URLSearchParams(t).get("q")??"";(0,r.useEffect)(()=>{u(n)},[n])}function u(e){window.dispatchEvent(new CustomEvent("blackbird_monolith_update_input",{detail:e}))}function d({appendQuery:e,retainScrollPosition:t,returnTarget:n}){window.dispatchEvent(new CustomEvent("blackbird_monolith_append_and_focus_input",{detail:{appendQuery:e,retainScrollPosition:t,returnTarget:n}}))}function f(){window.dispatchEvent(new CustomEvent("blackbird_provide_feedback"))}},90409:(e,t,n)=>{n.d(t,{z:()=>s});var r=n(67294),o=n(96974),i=n(10866);function s(e){let t=(0,o.s0)();return(0,r.useCallback)((n,r,o)=>{let s=(0,i.Gr)(e,n,r);t(s,o)},[t,e])}},98950:(e,t,n)=>{function r(e){let t=document.createElement("pre");return t.style.width="1px",t.style.height="1px",t.style.position="fixed",t.style.top="5px",t.textContent=e,t}function o(e){if("clipboard"in navigator)return navigator.clipboard.writeText(e.textContent||"");let t=getSelection();if(null==t)return Promise.reject(Error());t.removeAllRanges();let n=document.createRange();return n.selectNodeContents(e),t.addRange(n),document.execCommand("copy"),t.removeAllRanges(),Promise.resolve()}function i(e){if("clipboard"in navigator)return navigator.clipboard.writeText(e);let t=document.body;if(!t)return Promise.reject(Error());let n=r(e);return t.appendChild(n),o(n),t.removeChild(n),Promise.resolve()}n.d(t,{z:()=>i})},54529:(e,t,n)=>{n.d(t,{C:()=>s,Z:()=>i});var r=n(44544);let o="blackbird_experiments";function i(){let e=(0,r.Z)("localStorage").getItem(o);return e?e.split(",").map(e=>parseInt(e)):[]}function s(e){(0,r.Z)("localStorage").setItem(o,e.join(","))}},81732:(e,t,n)=>{var r;function o(e){return!!e.qualifier}function i(e){return!!o(e)&&"Saved"===e.qualifier}n.d(t,{MO:()=>a,T$:()=>d,ZI:()=>u,az:()=>o,eH:()=>i,g8:()=>l,gq:()=>p,hs:()=>c,o8:()=>f,tT:()=>r}),function(e){e[e.Is=0]="Is",e[e.Repository=1]="Repository",e[e.Owner=2]="Owner",e[e.Language=3]="Language",e[e.Path=4]="Path",e[e.Regex=5]="Regex",e[e.Text=6]="Text",e[e.Saved=7]="Saved",e[e.OtherQualifier=8]="OtherQualifier"}(r||(r={}));let s=RegExp("\\/","g");function a(e,t){if(o(e)&&c(e.content)){if("Repo"===e.qualifier){if(1!=[...e.content.value.toString().matchAll(s)].length)return null}else if("Org"!==e.qualifier)return null;else if(0!=[...e.content.value.toString().matchAll(s)].length)return null;let n=`/${e.content.value.toString().split("/").map(encodeURIComponent).join("/")}`;return n===t?null:n}return null}function c(e){return void 0!==e.value}function l(e){return!!e.children}function u(e,t){if(o(e)&&e.qualifier===t)return!0;if(l(e)){for(let n of e.children)if(u(n,t))return!0}return!1}function d(e){return l(e)?e.children.map(d).filter(e=>e.length>0).join(" "):o(e)||"Regex"===e.kind?"":c(e)?e.value.toString():""}function f(e){if("Not"===e.kind)return[];if(l(e))return e.children.map(f).flat();if(o(e)){if("Repo"===e.qualifier&&c(e.content))return[{kind:"repo",value:e.content.value.toString()}];if("Org"===e.qualifier&&c(e.content))return[{kind:"org",value:e.content.value.toString()}];if(i(e)&&c(e.content))return[{kind:"saved",value:e.content.value.toString()}]}return[]}function p(e,t){let n=new Set(f(e).map(e=>"org"===e.kind?e.value:"repo"===e.kind&&e.value.includes("/")?e.value.split("/")[0]:null).filter(e=>null!==e).map(e=>e?.toLowerCase()));return 0===n.size?t:t.filter(e=>n.has(e.toLowerCase()))}},91691:(e,t,n)=>{n.r(t),n.d(t,{SearchType:()=>o.Sc,chooseSearchType:()=>b,extractUnsupportedQualifiers:()=>y,getCaretPositionKindFromIndex:()=>k,getCustomScopeNames:()=>l,getExpandedQuery:()=>d,getHighlights:()=>m,getPossibleQualifierValues:()=>o.i$,mapSearchTypeToURLParam:()=>C,mapURLParamToSearchType:()=>_,moveCaretToPosition:()=>p,parseSearchInput:()=>c,parseString:()=>a,searchTypeAsPlural:()=>w});var r,o=n(42537),i=n(81732);let s=String.fromCharCode(160);function a(e){let t=RegExp(s,"g");return(0,o.Qc)(e.replace(t," "))}function c(e){let t=a(e),n=m(t);g(n);let r=[],o=0;for(let t of n)if(o<=t.location.start){r.push(e.substring(o,t.location.start).replace(" ",String.fromCharCode(160))),o=t.location.start;let n=document.createElement("span");n.classList.add(t.className),n.textContent=e.substring(t.location.start,t.location.end),r.push(n),o=t.location.end}return o<e.length&&r.push(e.substring(o).replace(" ",s)),[t,r]}function l(e){let t=[];u(t,e);let n=t.map(e=>e.content.value.toString());return[...new Set(n)]}function u(e,t){if((0,i.eH)(t)&&(0,o.hs)(t.content)&&e.push(t),(0,i.g8)(t))for(t of t.children)u(e,t)}function d(e,t,n){let r="",i=[];u(i,n);let s=0;for(let n of i)if((0,o.hs)(n.content)){r+=e.substring(s,n.location.start);let i=t.find(e=>o.hs(n.content)&&e.name===n.content.value)?.query;i&&(r+=f(i)),s=n.content.location.end}return r+e.substring(s)}function f(e){return e.replaceAll(" OR "," ")}function p(e,t){let n=-1===t?e.value.length:t;e.focus(),e.setSelectionRange(n,n)}let h={And:{className:"pl-en",selector:"operatorLocation"},Not:{className:"pl-en",selector:"operatorLocation"},Or:{className:"pl-en",selector:"operatorLocation"},Regex:{className:"pl-c1",selector:"location"}};function m(e){let t;if((0,i.az)(e)&&S(e.content))t=[{className:"input-parsed-symbol",location:e.content.location}];else if(x(e)&&("AND"===e.value||"OR"===e.value||"NOT"===e.value))t=[{className:"pl-en",location:e.location}];else{let n=h[e.kind];n&&("location"===n.selector&&S(e)&&(t=[{className:n.className,location:e.location}]),"operatorLocation"===n.selector&&v(e)&&(t=e.operatorLocations.map(e=>({className:n.className,location:e}))))}return(t=t??[],(0,i.g8)(e))?t.concat(e.children.flatMap(m)):(0,i.az)(e)?t.concat(m(e.content)):t}function g(e){e.sort((e,t)=>e.location.start-t.location.start)}function x(e){return!!e.value}function S(e){return!!e.location}function v(e){return!!e.operatorLocations}function k(e,t){let n=function e(t,n){if((0,i.g8)(t))for(let r of t.children){let t=e(r,n);if(t)return t}if(S(t)){let e=t.location.start,r=t.location.end;if((0,i.az)(t)&&S(t.content)&&(r=t.content.location.end),n>=e&&n<=r)return t}}(e,t);if(!n)return{kind:i.tT.Text};if("Regex"===n.kind)return{kind:i.tT.Regex};if((0,i.az)(n)){if("Is"===n.qualifier)return{kind:i.tT.Is,node:n};if("Language"===n.qualifier)return{kind:i.tT.Language,node:n};if("Path"===n.qualifier)return{kind:i.tT.Path,node:n};if("Repo"===n.qualifier)return{kind:i.tT.Repository,node:n};else if("Owner"===n.qualifier)return{kind:i.tT.Owner,node:n};else if("Org"===n.qualifier)return{kind:i.tT.Owner,node:n};else if("Saved"===n.qualifier)return{kind:i.tT.Saved,node:n};else return{kind:i.tT.OtherQualifier,node:n}}return{kind:i.tT.Text,node:n}}function y(e,t){let n=[];return!function e(r){if((0,i.az)(r)&&!(0,o.Td)(t,r.qualifier))n.includes(r.qualifier)||n.push(r.qualifier);else if((0,i.az)(r)&&"Is"===r.qualifier){let e=r.content;if((0,o.hs)(e)){let r=e.value;t!==o.Sc.Issues&&"issue"===r?n.push("is:issue"):t!==o.Sc.PRs&&"pr"===r&&n.push("is:pr")}}if((0,i.g8)(r))for(let t of r.children)e(t)}(e),n}function b(e){let t={[o.Sc.Repositories]:.5,[o.Sc.Code]:.2,[o.Sc.Issues]:.1,[o.Sc.PRs]:0,[o.Sc.Discussions]:0,[o.Sc.Commits]:0,[o.Sc.Packages]:0,[o.Sc.Topics]:0,[o.Sc.Users]:0,[o.Sc.Orgs]:0,[o.Sc.Wikis]:0,[o.Sc.Marketplace]:-.4,[o.Sc.Unknown]:-1,[o.Sc.CodeLegacy]:-1},n=[];for(let r of(j(e,n),n)){let[e,n]=r;if(0===n)for(let n of e)t[n]+=1;else{let n={};for(let t of e)n[t]=!0;for(let e of Object.keys(t))n[e]||delete t[e]}}let r=Object.keys(t).map(e=>[e,t[e]]),i=o.Sc.Unknown;return r.length>0&&(r.sort((e,t)=>t[1]-e[1]),i=r[0][0]),i}function C(e){return({[o.Sc.Unknown]:"",[o.Sc.Code]:"code",[o.Sc.Repositories]:"repositories",[o.Sc.PRs]:"pullrequests",[o.Sc.Issues]:"issues",[o.Sc.Discussions]:"discussions",[o.Sc.Commits]:"commits",[o.Sc.Packages]:"registrypackages",[o.Sc.Marketplace]:"marketplace",[o.Sc.Topics]:"topics",[o.Sc.Users]:"users",[o.Sc.Orgs]:"users",[o.Sc.Wikis]:"wikis",[o.Sc.CodeLegacy]:"codelegacy"})[e]||""}function w(e){return({[o.Sc.Unknown]:"",[o.Sc.Code]:"code",[o.Sc.Repositories]:"repositories",[o.Sc.PRs]:"pull requests",[o.Sc.Issues]:"issues",[o.Sc.Discussions]:"discussions",[o.Sc.Commits]:"commits",[o.Sc.Packages]:"packages",[o.Sc.Marketplace]:"the marketplace",[o.Sc.Topics]:"topics",[o.Sc.Users]:"users",[o.Sc.Orgs]:"users",[o.Sc.Wikis]:"wikis",[o.Sc.CodeLegacy]:"code"})[e]||""}function _(e){return({"":o.Sc.Unknown,code:o.Sc.Code,repositories:o.Sc.Repositories,pullrequests:o.Sc.PRs,issues:o.Sc.Issues,discussions:o.Sc.Discussions,commits:o.Sc.Commits,registrypackages:o.Sc.Packages,marketplace:o.Sc.Marketplace,topics:o.Sc.Topics,users:o.Sc.Users,orgs:o.Sc.Orgs,wikis:o.Sc.Wikis,codelegacy:o.Sc.CodeLegacy})[e]||o.Sc.Unknown}function j(e,t){if((0,i.az)(e)){if(("Repo"===e.qualifier||"Org"===e.qualifier)&&t.push([[o.Sc.Code],0]),"Saved"===e.qualifier&&t.push([[o.Sc.Code],1]),(0,o.hs)(e.content)){"Regex"===e.content.kind&&t.push([[o.Sc.Code],1]);let n=e.content.value.toString().toLowerCase();if("Is"===e.qualifier)"pr"===n?t.push([[o.Sc.PRs],1]):"issue"===n?t.push([[o.Sc.Issues],1]):"sponsorable"===n&&t.push([[o.Sc.Users,o.Sc.Repositories],1]);else if("Type"===e.qualifier){let e=new Map([["commit",o.Sc.Commits],["discussion",o.Sc.Discussions],["issue",o.Sc.Issues],["marketplace",o.Sc.Marketplace],["org",o.Sc.Orgs],["package",o.Sc.Packages],["pr",o.Sc.PRs],["topic",o.Sc.Topics],["user",o.Sc.Users],["wiki",o.Sc.Wikis]]);e.has(n)&&t.push([[e.get(n)],0])}}let n=(0,o.PZ)(e.qualifier);n.length>0&&t.push([n,1])}else"Regex"===e.kind&&t.push([[o.Sc.Code],1]);if((0,i.g8)(e))for(let n of e.children)j(n,t)}!function(e){e[e.Hint=0]="Hint",e[e.Compatible=1]="Compatible"}(r||(r={}))},34232:(e,t,n)=>{n.d(t,{n:()=>a});var r,o=n(85893),i=n(67294),s=n(87487);function a({children:e,appName:t,category:n,metadata:r}){let a=(0,i.useMemo)(()=>({appName:t,category:n,metadata:r}),[t,n,r]);return(0,o.jsx)(s.f.Provider,{value:a,children:e})}try{(r=a).displayName||(r.displayName="AnalyticsProvider")}catch{}},87487:(e,t,n)=>{n.d(t,{f:()=>o});var r=n(67294);let o=(0,r.createContext)(null)},78806:(e,t,n)=>{n.d(t,{Z:()=>o});let r=(e,t)=>{let n=new URL(e,window.location.origin),r=new URL(t,window.location.origin),o=r.href.includes("#");return o&&n.host===r.host&&n.pathname===r.pathname&&n.search===r.search},o=r},2048:(e,t,n)=>{n.d(t,{g:()=>o,y:()=>i});var r=n(17891);let o=()=>r.M()?.enabled_features??{},i=e=>!!o()[e]},53664:(e,t,n)=>{n.d(t,{z:()=>s});var r=n(67294),o=n(95253),i=n(87487);function s(){let e=(0,r.useContext)(i.f);if(!e)throw Error("useAnalytics must be used within an AnalyticsContext");let{appName:t,category:n,metadata:s}=e;return{sendAnalyticsEvent:(0,r.useCallback)((e,r,i={})=>{let a={react:!0,app_name:t,category:n,...s};(0,o.q)(e,{...a,...i,target:r})},[t,n,s])}}},88455:(e,t,n)=>{n.d(t,{F:()=>o});var r=n(73968);function o(e,t){let{csrf_tokens:n}=(0,r.T)();return n?.[e]?.[t]}},68203:(e,t,n)=>{n.d(t,{s:()=>c});var r=n(67294),o=n(96974),i=n(78806),s=n(45055),a=n(68202);let c=()=>{let{routes:e,history:t}=r.useContext(s.I),c=(0,o.s0)();return r.useCallback((r,s)=>{let l=(0,o.i3)(r).pathname,u=!(0,o.fp)(e,l);if(u){let e=t.createHref(r);(async()=>{let{softNavigate:t}=await Promise.all([n.e("vendors-node_modules_github_turbo_dist_turbo_es2017-esm_js"),n.e("ui_packages_soft-navigate_soft-navigate_ts")]).then(n.bind(n,75198));t(e)})()}else{(0,i.Z)(location.href,r.toString())||(0,a.LD)("react"),c(r,s);let{turbo:e,...t}=window.history.state;window.history.replaceState({...t,skipTurbo:!0},"",location.href)}},[t,c,e])}},9220:(e,t,n)=>{n.d(t,{I:()=>s});var r,o=n(67294),i=n(88455);function s(e,t){let n=(0,i.F)(e,t);return(0,o.useCallback)(async r=>{let o=t;if(!n)throw Error(`No authenticity token found for method ${o} and path ${e}`);return r||(r={}),a(r,"X-Requested-With","XMLHttpRequest"),r.body instanceof URLSearchParams&&"delete"===o&&(r.body.append("_method","delete"),o="post"),r.body instanceof URLSearchParams||r.body instanceof FormData?r.body.append("authenticity_token",n):a(r,"Scoped-CSRF-Token",n),await fetch(e,{...r,method:o})},[e,t,n])}function a(e,t,n){(r=e).headers??(r.headers=new Headers);let o=e.headers;if(o instanceof Headers)o.set(t,n);else if(Array.isArray(o)){let e=o.findIndex(([e])=>e===t);-1===e?o.push([t,n]):o[e]=[t,n]}else o[t]=n}},59050:(e,t,n)=>{n.d(t,{C:()=>g,E:()=>x});var r,o=n(85893),i=n(75478),s=n(97011),a=n(73290);let c=6e4,l=36e5,u=24*l,d=30*u,f=[{unit:"month",ms:d},{unit:"day",ms:u},{unit:"hour",ms:l},{unit:"minute",ms:6e4},{unit:"second",ms:1e3}],p=new Intl.DateTimeFormat(void 0,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"numeric",second:void 0,timeZoneName:"short"}),h=new Intl.DateTimeFormat(void 0,{year:"numeric",month:"short",day:"numeric"}),m=new Intl.DateTimeFormat(void 0,{month:"short",day:"numeric"});function g(e,t=!0){let n="",r=new Date,o=r.getTime()-e.getTime(),i=f.find(e=>e.ms<o);if(i&&"month"!==i.unit){let e=Math.floor(o/i.ms);n="day"===i.unit&&1===e?"yesterday":`${e} ${i.unit}${e>1?"s":""} ago`}else{let o=e.getFullYear()===r.getFullYear()?m:h;n=`${t?"on ":""}${o.format(e)}`}return n}function x({timestamp:e,usePreposition:t=!0,linkUrl:n,sx:r}){let c=g(e,t),l=p.format(e);return n?(0,o.jsx)(a.Z,{sx:{color:"fg.muted",...r},href:n,target:"_blank",children:(0,o.jsx)(i.Z,{inline:!0,title:l,children:(0,o.jsx)(s.Z,{title:l,sx:{"&:hover, &:focus":{color:"accent.fg",textDecoration:"underline"}},children:c})})}):(0,o.jsx)(i.Z,{inline:!0,title:l,children:(0,o.jsx)(s.Z,{title:l,sx:r,children:c})})}try{(r=x).displayName||(r.displayName="Ago")}catch{}},71091:(e,t,n)=>{n.d(t,{v:()=>N});var r,o,i,s,a,c=n(85893),l=n(85529),u=n(71067),d=n(42483),f=n(50919),p=n(12470),h=n(50901),m=n(74121),g=n(67294),x=n(38490),S=n(73290),v=n(26012),k=n(97011);function y({checkRun:e}){let{icon:t,iconColor:n}=b(e.icon),r="in_progress"===e.state;return(0,c.jsxs)(d.Z,{"data-testid":"check-run-item",sx:{display:"flex",borderBottomWidth:"1px",borderBottomStyle:"solid",borderBottomColor:"border.default",backgroundColor:"canvas.subtle",height:"38px",py:2,pr:3,pl:"12px",alignItems:"baseline"},children:[r?C():(0,c.jsx)(u.Z,{icon:t,sx:{color:n,margin:"0px 7px",alignSelf:"center"}}),(0,c.jsx)(x.Z,{"aria-label":e.avatarDescription,direction:"e",children:(0,c.jsx)(S.Z,{href:e.avatarUrl,sx:{mr:2},children:(0,c.jsx)(v.Z,{square:!0,src:e.avatarLogo,sx:{backgroundColor:e.avatarBackgroundColor}})})}),(0,c.jsxs)(k.Z,{sx:{overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",fontSize:"13px",color:"fg.muted"},children:[(0,c.jsxs)(k.Z,{sx:{fontWeight:"bold",color:"fg.default",mr:"2px"},children:[e.name," "]}),e.pending?(0,c.jsx)(k.Z,{sx:{fontStyle:"italic"},children:e.additionalContext}):e.additionalContext,e.description&&(0,c.jsxs)(k.Z,{children:[" ","- ",e.pending?(0,c.jsx)(k.Z,{sx:{fontStyle:"italic"},children:e.description}):e.description]})]}),(0,c.jsx)(S.Z,{href:e.targetUrl,sx:{pl:"12px",fontSize:"13px",marginLeft:"auto"},children:"Details"})]})}function b(e){switch(e){case"check":return{icon:l.nQG,iconColor:"success.fg"};case"dot-fill":return{icon:l.ydi,iconColor:"attention.fg"};case"stop":return{icon:l.wNq,iconColor:"muted.fg"};case"issue-reopened":return{icon:l.eJg,iconColor:"muted.fg"};case"clock":return{icon:l.T39,iconColor:"attention.fg"};case"square-fill":return{icon:l.QU,iconColor:"fg.default"};case"skip":return{icon:l.C4D,iconColor:"muted.fg"};case"alert":return{icon:l.zMQ,iconColor:"danger.fg"};default:return{icon:l.b0D,iconColor:"danger.fg"}}}function C(){return(0,c.jsx)(d.Z,{sx:{height:"16px",width:"16px",minWidth:"16px",alignSelf:"center",mx:"7px"},children:(0,c.jsxs)("svg",{fill:"none",viewBox:"0 0 16 16",className:"anim-rotate","aria-hidden":"true",role:"img",children:[(0,c.jsx)("path",{opacity:".5",d:"M8 15A7 7 0 108 1a7 7 0 000 14v0z",stroke:"#dbab0a",strokeWidth:"2"}),(0,c.jsx)("path",{d:"M15 8a7 7 0 01-7 7",stroke:"#dbab0a",strokeWidth:"2"}),(0,c.jsx)("path",{d:"M8 12a4 4 0 100-8 4 4 0 000 8z",fill:"#dbab0a"})]})})}try{(r=y).displayName||(r.displayName="CheckRunItem")}catch{}function w({checkRuns:e}){return(0,c.jsx)(d.Z,{sx:{display:"flex",flexDirection:"column",maxHeight:"230px",overflow:"auto"},children:e.map((e,t)=>(0,c.jsx)(y,{checkRun:e},t))})}try{(o=w).displayName||(o.displayName="ChecksStatusBadgeFooter")}catch{}function _({checksHeaderState:e,checksStatusSummary:t}){return(0,c.jsx)(d.Z,{sx:{display:"flex",paddingX:3,paddingBottom:3,borderBottomWidth:"1px",borderBottomStyle:"solid",borderBottomColor:"border.default"},children:(0,c.jsxs)(d.Z,{sx:{pr:2,display:"flex",flexDirection:"column"},children:[(0,c.jsx)(j,{checksHeaderState:e}),(0,c.jsx)(k.Z,{sx:{color:"fg.muted",fontSize:0,mt:"1px"},children:t})]})})}function j({checksHeaderState:e}){switch(e){case"SUCCEEDED":return(0,c.jsx)(k.Z,{sx:{fontWeight:"bold",fontSize:2},children:"All checks have passed"});case"FAILED":return(0,c.jsx)(k.Z,{sx:{color:"checks.donutError",fontWeight:"bold",fontSize:2},children:"All checks have failed"});case"PENDING":return(0,c.jsx)(k.Z,{sx:{color:"checks.donutPending",fontWeight:"bold",fontSize:2},children:"Some checks haven\u2019t completed yet"});default:return(0,c.jsx)(k.Z,{sx:{color:"checks.donutError",fontWeight:"bold",fontSize:2},children:"Some checks were not successful"})}}try{(i=_).displayName||(i.displayName="ChecksStatusBadgeHeader")}catch{}try{(s=j).displayName||(s.displayName="HeaderState")}catch{}let R={success:{circled:l.rE2,filled:l.kD1,default:l.nQG,color:"checks.donutSuccess"},pending:{circled:l.J$M,filled:l.ydi,default:l.ydi,color:"checks.donutPending"},error:{circled:l.oOx,filled:l.S7k,default:l.b0D,color:"checks.donutError"}};function N(e){let{statusRollup:t,combinedStatus:n,variant:r="default",disablePopover:o,size:i="medium"}=e,[s,a]=(0,g.useState)(!1),l=(0,g.useRef)(null),x=R[t],{icon:S,iconColor:v}={icon:x?.[r]||R.error[r],iconColor:x?.color||R.error.color};return o?(0,c.jsx)("span",{"data-testid":"checks-status-badge-icon-only",children:(0,c.jsx)(u.Z,{icon:S,"aria-label":"See all checks",sx:{color:v}})}):(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)(d.Z,{onClick:()=>{a(!0),e.onWillOpenPopup},onMouseEnter:e.onWillOpenPopup,children:(0,c.jsx)(f.h,{"data-testid":"checks-status-badge-icon",icon:S,variant:"invisible",size:i,"aria-label":n?.checksStatusSummary??t,sx:{py:0,px:0,mr:2,svg:{color:v},":hover:not([disabled])":{bg:"pageHeaderBg"}},ref:l})}),(0,c.jsx)(p.Z,{isOpen:s,onDismiss:()=>a(!1),returnFocusRef:l,sx:{overflowY:"auto",pt:3},children:(0,c.jsx)(h.S,{sx:{padding:0},children:n?(0,c.jsxs)(c.Fragment,{children:[(0,c.jsx)(_,{checksHeaderState:n.checksHeaderState,checksStatusSummary:n.checksStatusSummary}),(0,c.jsx)(w,{checkRuns:n.checkRuns})]}):(0,c.jsx)(d.Z,{sx:{display:"flex",justifyContent:"center",p:2},children:(0,c.jsx)(m.Z,{size:"medium"})})})})]})}try{(a=N).displayName||(a.displayName="ChecksStatusBadge")}catch{}},26465:(e,t,n)=>{n.d(t,{Z:()=>i});var r,o=n(85893);function i(){return(0,o.jsx)("div",{className:"Popover js-hovercard-content position-absolute",style:{display:"none",outline:"none"},tabIndex:0,children:(0,o.jsx)("div",{className:"Popover-message Popover-message--bottom-left Popover-message--large Box color-shadow-large",style:{width:"360px"}})})}try{(r=i).displayName||(r.displayName="HoverCard")}catch{}},90874:(e,t,n)=>{n.d(t,{M:()=>c,x:()=>l});var r,o,i=n(85893),s=n(67294);let a=s.createContext(void 0);function c({user:e,children:t}){return(0,i.jsxs)(a.Provider,{value:e,children:[" ",t," "]})}function l(){return s.useContext(a)}try{(r=a).displayName||(r.displayName="CurrentUserContext")}catch{}try{(o=c).displayName||(o.displayName="CurrentUserProvider")}catch{}},34493:(e,t,n)=>{n.d(t,{o:()=>l,x:()=>u});var r,o,i=n(85893),s=n(86283),a=n(67294);let c=a.createContext({focusHint:null,setFocusHint:()=>void 0});function l({children:e}){let t={key:s.jX.pathname+s.jX.search},n=(0,a.useRef)(t.key),r=(0,a.useRef)(t.key),o=(0,a.useRef)({hint:null,location:null}),l=(0,a.useCallback)((e,n)=>{o.current={hint:e,context:n,location:t.key}},[t.key]);r.current!==t.key&&(n.current=r.current,r.current=t.key);let u=o.current.location===n.current,d=u?o.current.hint:null,f=u?o.current.context:null,p=(0,a.useMemo)(()=>({focusHint:d,context:f,setFocusHint:l}),[d,f,l]);return(0,i.jsx)(c.Provider,{value:p,children:e})}function u(){return(0,a.useContext)(c)}try{(r=c).displayName||(r.displayName="FocusHintContext")}catch{}try{(o=l).displayName||(o.displayName="FocusHintContextProvider")}catch{}}}]);
//# sourceMappingURL=app_assets_modules_blackbird-monolith_hooks_use-navigate-to-query_ts-app_assets_modules_black-182e14-d8711b990401.js.map