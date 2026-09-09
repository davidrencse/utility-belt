#!/usr/bin/env python3
"""
Standalone Three.js "Geo / Infrastructure" visualization for a scan target.

Three views, switchable in the HUD, camera tweens between them:

  GLOBE  - a wireframe/dotted Earth with the target geopinned by lat/lon
           (glowing pin, pulsing rings, vertical beam, city/country label),
           plus a great-circle arc from your own location when available.
  STREET - a STYLISED city block centred on those coordinates with the
           target building highlighted. Clearly labelled "approximate" —
           IP geolocation is city-level, not a surveyed address.
  INFRA  - procedural 3D models: your laptop (from real specs), the target
           as a server rack, and a row of data-center racks behind it,
           with blinking drive/status LEDs and a link from laptop → target.

Self-contained: Three.js is vendored at ./vendor/three.min.js and copied
next to the generated HTML (CDN fallback if missing), so it runs offline.
"""

import json
import os
import shutil
import tempfile
import webbrowser

VENDOR_THREE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "three.min.js")
THREE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"

_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>__TARGET__ — Geo &amp; Infrastructure</title>
<style>
  :root { --bg:#0a0a0c; --card:#17171c; --border:#2a2a31; --fg:#f4f2ec;
          --muted:#8a8a93; --accent:#ff5a1f; --amber:#d68a2e; }
  html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
            font-family:Consolas,"Courier New",monospace;overflow:hidden;}
  #scene{display:block;width:100vw;height:100vh;cursor:grab;}
  #scene:active{cursor:grabbing;}
  .ov{position:fixed;pointer-events:none;}
  #top{top:0;left:0;right:0;padding:16px 20px;display:flex;justify-content:space-between;align-items:flex-start;}
  .brand{font-size:15px;font-weight:bold;letter-spacing:2px;}
  .brand .d{color:var(--accent);}
  .sub{font-size:11px;color:var(--muted);margin-top:4px;}
  #views{pointer-events:auto;display:flex;gap:8px;}
  .vbtn{background:var(--card);border:1px solid var(--border);color:var(--muted);
        border-radius:14px;padding:8px 16px;font:bold 11px Consolas,monospace;
        letter-spacing:1px;cursor:pointer;}
  .vbtn.active{background:var(--accent);color:#0a0500;border-color:var(--accent);}
  .panel{background:rgba(18,18,22,.82);border:1px solid var(--border);border-radius:14px;
         padding:12px 14px;backdrop-filter:blur(3px);width:280px;}
  .panel h2{margin:0 0 9px;font-size:9px;letter-spacing:2px;color:var(--accent);}
  .row{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:11px;}
  .row .k{color:var(--muted);white-space:nowrap;}
  .row .v{color:var(--fg);text-align:right;overflow:hidden;text-overflow:ellipsis;
          white-space:nowrap;max-width:180px;}
  #left{left:20px;top:92px;}
  #right{right:20px;top:92px;}
  #note{bottom:16px;left:20px;font-size:10px;color:#5a5852;max-width:60vw;}
  #hint{bottom:16px;right:20px;font-size:10px;color:#4a4844;letter-spacing:1px;}
  #tip{position:fixed;display:none;background:#0c0c0d;border:1px solid var(--border);
       border-radius:8px;padding:8px 10px;font-size:11px;z-index:9;}
  #fallback{position:fixed;inset:0;display:none;align-items:center;justify-content:center;
            text-align:center;padding:40px;color:var(--muted);}
</style>
</head>
<body>
<canvas id="scene"></canvas>
<div class="ov" id="top">
  <div>
    <div class="brand"><span class="d">●</span> GEO // INFRASTRUCTURE</div>
    <div class="sub" id="sub"></div>
  </div>
  <div id="views">
    <button class="vbtn active" data-v="globe">GLOBE</button>
    <button class="vbtn" data-v="street">STREET</button>
    <button class="vbtn" data-v="infra">INFRA</button>
  </div>
</div>
<div class="ov panel" id="left"></div>
<div class="ov panel" id="right"></div>
<div class="ov" id="note"></div>
<div class="ov" id="hint">drag to orbit · scroll to zoom · buttons switch view</div>
<div id="tip"></div>
<div id="fallback">Three.js could not be loaded.<br>Expected three.min.js beside this file or an internet connection.</div>

<script src="three.min.js"></script>
<script>
if (typeof THREE === 'undefined') { document.write('<scr'+'ipt src="__THREE_CDN__"><\/scr'+'ipt>'); }
</script>
<script>
const DATA = __DATA_JSON__;
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function row(k,v){return (v==null||v==='')?'':`<div class="row"><span class="k">${esc(k)}</span><span class="v" title="${esc(v)}">${esc(v)}</span></div>`;}

/* ---------------- HUD ---------------- */
(function(){
  const g = DATA.geo || {}, s = DATA.specs || {}, sc = DATA.scan || {};
  document.getElementById('sub').textContent = `${DATA.target} (${DATA.ip})`;
  let geoHtml = '<h2>GEOLOCATION</h2>';
  if (g.ok){
    geoHtml += row('CITY', g.city) + row('REGION', g.regionName) + row('COUNTRY', g.country)
      + row('LAT / LON', (g.lat+', '+g.lon)) + row('ORG', g.org || g.isp) + row('ASN', g.as)
      + row('TIMEZONE', g.timezone);
  } else {
    geoHtml += row('STATUS', g.private ? 'Private / LAN' : 'Unavailable') + row('NOTE', g.message);
  }
  document.getElementById('left').innerHTML = geoHtml;
  document.getElementById('right').innerHTML = '<h2>TARGET &amp; SCAN</h2>'
    + row('TARGET', DATA.target) + row('ADDRESS', DATA.ip)
    + row('OPEN', sc.open) + row('CLOSED', sc.closed) + row('FILTERED', sc.filtered)
    + row('PORTS', sc.total)
    + '<h2 style="margin-top:12px">THIS MACHINE</h2>'
    + row('MODEL', s.model) + row('CPU', s.cpu) + row('GPU', s.gpu);
  document.getElementById('note').textContent =
    'Note: IP geolocation is city-level (ISP registration) — the street/building view is a stylised representation of these coordinates, not a surveyed address.';
})();

if (typeof THREE === 'undefined'){ document.getElementById('fallback').style.display='flex'; }
else { boot(); }

function boot(){
  const canvas=document.getElementById('scene');
  const renderer=new THREE.WebGLRenderer({canvas,antialias:true});
  renderer.setPixelRatio(Math.min(window.devicePixelRatio,2));
  renderer.outputEncoding=THREE.sRGBEncoding;
  const scene=new THREE.Scene();
  scene.background=new THREE.Color(0x0a0a0c);
  scene.fog=new THREE.Fog(0x0a0a0c,60,180);
  const camera=new THREE.PerspectiveCamera(45,1,0.1,600);

  scene.add(new THREE.AmbientLight(0x3a3d46,0.8));
  const key=new THREE.DirectionalLight(0xdfe6ff,0.7); key.position.set(10,16,12); scene.add(key);
  const rim=new THREE.DirectionalLight(0xff5a1f,0.5); rim.position.set(-10,6,-8); scene.add(rim);

  const ACCENT=0xff5a1f, AMBER=0xd68a2e;
  const matA=new THREE.MeshBasicMaterial({color:ACCENT});
  const matAmber=new THREE.MeshBasicMaterial({color:AMBER});

  function glowTex(){
    const c=document.createElement('canvas');c.width=c.height=128;
    const x=c.getContext('2d');const gr=x.createRadialGradient(64,64,0,64,64,64);
    gr.addColorStop(0,'rgba(255,150,90,.95)');gr.addColorStop(.35,'rgba(255,90,31,.5)');gr.addColorStop(1,'rgba(255,90,31,0)');
    x.fillStyle=gr;x.fillRect(0,0,128,128);return new THREE.CanvasTexture(c);
  }
  const GLOW=glowTex();
  function glow(size,op){const s=new THREE.Sprite(new THREE.SpriteMaterial({map:GLOW,transparent:true,blending:THREE.AdditiveBlending,depthWrite:false,opacity:op==null?0.9:op}));s.scale.set(size,size,1);return s;}
  function label(text,color){
    const pad=14,fs=42;const c=document.createElement('canvas');let x=c.getContext('2d');
    x.font=`bold ${fs}px Consolas,monospace`;const w=Math.ceil(x.measureText(text).width)+pad*2;
    c.width=w;c.height=Math.round(fs*1.6);x=c.getContext('2d');x.font=`bold ${fs}px Consolas,monospace`;
    x.fillStyle=color||'#ffd9c4';x.textBaseline='middle';x.fillText(text,pad,c.height/2);
    const sp=new THREE.Sprite(new THREE.SpriteMaterial({map:new THREE.CanvasTexture(c),transparent:true,depthWrite:false}));
    sp.scale.set((c.width/c.height)*1.1,1.1,1);return sp;
  }
  function box(w,h,d,x,y,z,mat){const m=new THREE.Mesh(new THREE.BoxGeometry(w,h,d),mat);m.position.set(x,y,z);return m;}

  const leds=[];  // {mesh, on-color, phase}

  /* ===================== GLOBE ===================== */
  const globeGroup=new THREE.Group(); scene.add(globeGroup);
  const R=10;
  function latLon(lat,lon,r){
    const p=(90-lat)*Math.PI/180, t=(lon+180)*Math.PI/180;
    return new THREE.Vector3(-(r*Math.sin(p)*Math.cos(t)), r*Math.cos(p), r*Math.sin(p)*Math.sin(t));
  }
  (function buildGlobe(){
    globeGroup.add(new THREE.Mesh(new THREE.SphereGeometry(R*0.995,48,32),
      new THREE.MeshStandardMaterial({color:0x11141c,metalness:0.2,roughness:0.9})));
    // dotted surface
    const pts=[];
    for(let i=0;i<1600;i++){
      const y=1-(i/1599)*2, rr=Math.sqrt(1-y*y), th=i*2.399963;
      pts.push(Math.cos(th)*rr*R, y*R, Math.sin(th)*rr*R);
    }
    const pg=new THREE.BufferGeometry(); pg.setAttribute('position',new THREE.Float32BufferAttribute(pts,3));
    globeGroup.add(new THREE.Points(pg,new THREE.PointsMaterial({color:0x2f3444,size:0.12})));
    // graticule
    const gmat=new THREE.LineBasicMaterial({color:0x2a2f3c,transparent:true,opacity:0.55});
    for(let lat=-60;lat<=60;lat+=30){const seg=[];for(let lon=-180;lon<=180;lon+=6){const a=latLon(lat,lon,R*1.001),b=latLon(lat,lon+6,R*1.001);seg.push(a.x,a.y,a.z,b.x,b.y,b.z);}const gg=new THREE.BufferGeometry();gg.setAttribute('position',new THREE.Float32BufferAttribute(seg,3));globeGroup.add(new THREE.LineSegments(gg,gmat));}
    for(let lon=-180;lon<180;lon+=30){const seg=[];for(let lat=-90;lat<90;lat+=6){const a=latLon(lat,lon,R*1.001),b=latLon(lat+6,lon,R*1.001);seg.push(a.x,a.y,a.z,b.x,b.y,b.z);}const gg=new THREE.BufferGeometry();gg.setAttribute('position',new THREE.Float32BufferAttribute(seg,3));globeGroup.add(new THREE.LineSegments(gg,gmat));}
  })();
  const globePins=[];  // pulsing rings
  function addGlobePin(lat,lon,text,color){
    const p=latLon(lat,lon,R), out=p.clone().multiplyScalar(1.0), up=p.clone().normalize();
    const beamLen=3.2, mid=p.clone().add(up.clone().multiplyScalar(beamLen/2));
    const beam=box(0.08,beamLen,0.08,0,0,0,new THREE.MeshBasicMaterial({color}));
    beam.position.copy(mid); beam.quaternion.setFromUnitVectors(new THREE.Vector3(0,1,0),up);
    globeGroup.add(beam);
    const orb=new THREE.Mesh(new THREE.SphereGeometry(0.3,16,12),new THREE.MeshBasicMaterial({color}));
    orb.position.copy(p.clone().add(up.clone().multiplyScalar(beamLen))); globeGroup.add(orb);
    const gl=glow(3.0,0.9); gl.position.copy(orb.position); globeGroup.add(gl);
    const lb=label(text,'#ffd9c4'); lb.position.copy(orb.position.clone().add(up.clone().multiplyScalar(1.4))); globeGroup.add(lb);
    // ring on surface
    const ring=new THREE.Mesh(new THREE.RingGeometry(0.5,0.62,32),new THREE.MeshBasicMaterial({color,side:THREE.DoubleSide,transparent:true,opacity:0.8}));
    ring.position.copy(p); ring.quaternion.setFromUnitVectors(new THREE.Vector3(0,0,1),up); globeGroup.add(ring);
    globePins.push({ring,base:p});
  }
  function arc(a,b,color){
    const va=a.clone().normalize(),vb=b.clone().normalize();
    const pts=[],N=64,ang=va.angleTo(vb);
    for(let i=0;i<=N;i++){const t=i/N;
      // slerp
      const s=Math.sin(ang);let v;
      if(s<1e-4){v=va.clone();}else{v=va.clone().multiplyScalar(Math.sin((1-t)*ang)/s).add(vb.clone().multiplyScalar(Math.sin(t*ang)/s));}
      const lift=1+Math.sin(Math.PI*t)*0.35;
      v.multiplyScalar(R*lift);pts.push(v);
    }
    const gg=new THREE.BufferGeometry().setFromPoints(pts);
    globeGroup.add(new THREE.Line(gg,new THREE.LineBasicMaterial({color,transparent:true,opacity:0.85})));
  }
  if(DATA.geo && DATA.geo.ok){
    addGlobePin(DATA.geo.lat, DATA.geo.lon, (DATA.geo.city||DATA.target), ACCENT);
    if(DATA.self && DATA.self.ok){
      addGlobePin(DATA.self.lat, DATA.self.lon, (DATA.self.city||'you'), AMBER);
      arc(latLon(DATA.self.lat,DATA.self.lon,R), latLon(DATA.geo.lat,DATA.geo.lon,R), ACCENT);
    }
  } else {
    const lb=label(DATA.geo && DATA.geo.private ? 'PRIVATE / LAN — no geo' : 'GEO UNAVAILABLE','#8a8a93');
    lb.position.set(0,R+3,0); lb.scale.multiplyScalar(1.4); globeGroup.add(lb);
  }

  /* ===================== STREET ===================== */
  const streetGroup=new THREE.Group(); streetGroup.visible=false; scene.add(streetGroup);
  (function buildStreet(){
    const gmat=new THREE.LineBasicMaterial({color:0x24252b,transparent:true,opacity:0.6});
    const span=60,step=6,seg=[];
    for(let i=-span;i<=span;i+=step){seg.push(-span,0,i, span,0,i, i,0,-span, i,0,span);}
    const gg=new THREE.BufferGeometry();gg.setAttribute('position',new THREE.Float32BufferAttribute(seg,3));
    streetGroup.add(new THREE.LineSegments(gg,gmat));
    const bmat=new THREE.MeshStandardMaterial({color:0x1a1c22,metalness:0.3,roughness:0.85});
    const wmat=new THREE.MeshStandardMaterial({color:0x0e0f13,metalness:0.2,roughness:0.9,emissive:0x14161d});
    let seed=1234; const rnd=()=>{seed=(seed*1103515245+12345)&0x7fffffff;return seed/0x7fffffff;};
    for(let gx=-4;gx<=4;gx++)for(let gz=-4;gz<=4;gz++){
      if(gx===0&&gz===0)continue;
      const h=3+rnd()*11, w=3.4+rnd()*1.2;
      const b=box(w,h,w, gx*6, h/2, gz*6, rnd()>0.5?bmat:wmat); streetGroup.add(b);
    }
    // target building — tall, highlighted
    const th=16;
    const t=box(4.2,th,4.2,0,th/2,0,new THREE.MeshStandardMaterial({color:0x241108,metalness:0.4,roughness:0.5,emissive:0x2a0f04}));
    streetGroup.add(t);
    for(let i=1;i<8;i++) streetGroup.add(box(4.24,0.08,4.24,0,i*2,0,matA)); // floor accent bands
    // pin above building
    const beam=box(0.14,6,0.14,0,th+3,0,new THREE.MeshBasicMaterial({color:ACCENT})); streetGroup.add(beam);
    const orb=new THREE.Mesh(new THREE.SphereGeometry(0.6,18,14),new THREE.MeshBasicMaterial({color:ACCENT}));
    orb.position.set(0,th+6.4,0); streetGroup.add(orb);
    const gl=glow(5,0.9); gl.position.copy(orb.position); streetGroup.add(gl);
    const geo=DATA.geo||{};
    const lab=(geo.ok?((geo.city||'')+(geo.regionName?', '+geo.regionName:'')):'target')+' (approx)';
    const lb=label(lab,'#ffd9c4'); lb.position.set(0,th+8.2,0); lb.scale.multiplyScalar(1.4); streetGroup.add(lb);
    const ring=new THREE.Mesh(new THREE.TorusGeometry(6,0.06,8,64),new THREE.MeshBasicMaterial({color:0x7a2e10}));
    ring.rotation.x=Math.PI/2; ring.position.y=0.05; streetGroup.add(ring);
  })();

  /* ===================== INFRA ===================== */
  const infraGroup=new THREE.Group(); infraGroup.visible=false; scene.add(infraGroup);
  const caseMat=new THREE.MeshStandardMaterial({color:0x14151a,metalness:0.7,roughness:0.5});
  const caseMat2=new THREE.MeshStandardMaterial({color:0x1c1e25,metalness:0.6,roughness:0.55});
  const screenMat=new THREE.MeshStandardMaterial({color:0x0a0c12,metalness:0.2,roughness:0.4,emissive:0x2a1408});
  const railMat=new THREE.MeshStandardMaterial({color:0x2a2c34,metalness:0.85,roughness:0.35});
  function led(x,y,z,color){
    const m=new THREE.Mesh(new THREE.BoxGeometry(0.09,0.09,0.05),new THREE.MeshBasicMaterial({color}));
    m.position.set(x,y,z); leds.push({mesh:m,color,phase:Math.random()*6.28}); return m;
  }
  function buildLaptop(){
    const g=new THREE.Group();
    g.add(box(4.4,0.22,3.0,0,0.11,0,caseMat));              // base
    g.add(box(3.6,0.02,1.4,0,0.24,0.1,caseMat2));           // keyboard deck
    g.add(box(1.5,0.02,0.7,0,0.24,1.0,caseMat2));           // trackpad
    const lid=new THREE.Group();
    lid.add(box(4.4,3.0,0.14,0,1.5,0,caseMat));             // lid
    lid.add(box(4.0,2.6,0.03,0,1.5,0.09,screenMat));        // screen
    lid.add(box(4.0,0.05,0.04,0,2.74,0.1,matA));            // top glow line
    lid.position.set(0,0.22,-1.5); lid.rotation.x=-0.35; g.add(lid);
    g.add(led(-1.9,0.24,1.3,ACCENT));
    return g;
  }
  function buildRack(hx,hz,label_txt){
    const g=new THREE.Group(); const W=3.2,H=8.5,D=3.2;
    g.add(box(W,H,D,0,H/2,0,caseMat));
    g.add(box(W*0.92,H*0.96,0.06,0,H/2,D/2,new THREE.MeshStandardMaterial({color:0x090a0e,metalness:0.3,roughness:0.7}))); // smoked door
    for(let u=0;u<11;u++){
      const y=0.7+u*0.72;
      g.add(box(W*0.88,0.5,0.05,0,y,D/2+0.02,caseMat2));    // 1U face
      g.add(box(W*0.4,0.34,0.04,-0.55,y,D/2+0.05,railMat)); // drive bay
      g.add(led(0.7,y,D/2+0.06, (u%4===0)?ACCENT:AMBER));
      g.add(led(0.95,y,D/2+0.06, 0x39ff88));
    }
    g.position.set(hx,0,hz);
    if(label_txt){const lb=label(label_txt,'#ffd9c4'); lb.position.set(hx,H+1,hz); g.add(lb);}
    return g;
  }
  (function buildInfra(){
    const floor=new THREE.Mesh(new THREE.PlaneGeometry(80,80),new THREE.MeshStandardMaterial({color:0x101116,metalness:0.4,roughness:0.8}));
    floor.rotation.x=-Math.PI/2; infraGroup.add(floor);
    const gmat=new THREE.LineBasicMaterial({color:0x24252b,transparent:true,opacity:0.5});
    const seg=[];for(let i=-40;i<=40;i+=4){seg.push(-40,0.01,i,40,0.01,i,i,0.01,-40,i,0.01,40);}
    const gg=new THREE.BufferGeometry();gg.setAttribute('position',new THREE.Float32BufferAttribute(seg,3));
    infraGroup.add(new THREE.LineSegments(gg,gmat));
    // your laptop (left)
    const lap=buildLaptop(); lap.position.set(-14,0,6); lap.scale.setScalar(1.1); infraGroup.add(lap);
    infraGroup.add((function(){const lb=label((DATA.specs&&DATA.specs.model)?DATA.specs.model:'YOUR LAPTOP','#ffd9c4');lb.position.set(-14,4.2,6);return lb;})());
    // target server (center-front)
    infraGroup.add(buildRack(-4,0,'TARGET · '+DATA.ip));
    // data-center rows (behind)
    for(let r=0;r<3;r++)for(let cc=0;cc<5;cc++){ if(r===0&&cc===0)continue; infraGroup.add(buildRack(4+cc*4.2,-6-r*5,null)); }
    infraGroup.add((function(){const lb=label('DATA CENTER','#8a8a93');lb.position.set(12,10,-11);lb.scale.multiplyScalar(1.3);return lb;})());
    // link laptop -> target
    const lp=new THREE.Vector3(-14,1.6,6), tp=new THREE.Vector3(-4,5,1.7);
    const link=new THREE.Line(new THREE.BufferGeometry().setFromPoints([lp,tp]),new THREE.LineBasicMaterial({color:ACCENT,transparent:true,opacity:0.5}));
    infraGroup.add(link);
  })();

  /* ===================== camera / views ===================== */
  const POSES={
    globe:{tx:0,ty:0,tz:0, r:26, phi:1.05, theta:0.7, auto:true},
    street:{tx:0,ty:6,tz:0, r:46, phi:1.15, theta:0.8, auto:false},
    infra:{tx:-2,ty:3,tz:-2, r:40, phi:1.02, theta:0.9, auto:false},
  };
  let view='globe';
  let tgt={x:0,y:0,z:0}, camR=26, camPhi=1.05, camTheta=0.7, auto=true;
  let want=Object.assign({},POSES.globe);
  function setView(v){
    view=v; want={tx:POSES[v].tx,ty:POSES[v].ty,tz:POSES[v].tz,r:POSES[v].r,phi:POSES[v].phi,theta:POSES[v].theta};
    auto=POSES[v].auto;
    globeGroup.visible=(v==='globe'); streetGroup.visible=(v==='street'); infraGroup.visible=(v==='infra');
    document.querySelectorAll('.vbtn').forEach(b=>b.classList.toggle('active',b.dataset.v===v));
  }
  document.querySelectorAll('.vbtn').forEach(b=>b.addEventListener('click',()=>setView(b.dataset.v)));

  function place(){
    const sp=Math.sin(camPhi),cp=Math.cos(camPhi);
    camera.position.set(tgt.x+camR*sp*Math.cos(camTheta), tgt.y+camR*cp, tgt.z+camR*sp*Math.sin(camTheta));
    camera.lookAt(tgt.x,tgt.y,tgt.z);
  }
  function resize(){const w=window.innerWidth,h=window.innerHeight;renderer.setSize(w,h,false);camera.aspect=w/h;camera.updateProjectionMatrix();}
  window.addEventListener('resize',resize); resize();

  let drag=null;
  canvas.addEventListener('mousedown',e=>{drag=[e.clientX,e.clientY];auto=false;});
  window.addEventListener('mouseup',()=>drag=null);
  window.addEventListener('mousemove',e=>{if(!drag)return;camTheta-=(e.clientX-drag[0])*0.006;camPhi=Math.max(0.16,Math.min(1.45,camPhi-(e.clientY-drag[1])*0.005));drag=[e.clientX,e.clientY];});
  canvas.addEventListener('wheel',e=>{camR=Math.max(6,Math.min(140,camR*(e.deltaY>0?1.08:0.92)));e.preventDefault();},{passive:false});

  const clock=new THREE.Clock();
  function animate(){
    const t=clock.getElapsedTime();
    // ease camera toward wanted pose
    tgt.x+=(want.tx-tgt.x)*0.08; tgt.y+=(want.ty-tgt.y)*0.08; tgt.z+=(want.tz-tgt.z)*0.08;
    camR+=(want.r-camR)*0.06; camPhi+=(want.phi-camPhi)*0.08;
    if(auto) camTheta+=0.0015;
    place();
    for(const p of globePins){const k=1+Math.sin(t*2.2)*0.25;p.ring.scale.setScalar(k);p.ring.material.opacity=0.8-(k-1);}
    for(const l of leds){const on=(Math.sin(t*3+l.phase)>0);l.mesh.material.color.setHex(on?l.color:0x20222a);}
    renderer.render(scene,camera);
    requestAnimationFrame(animate);
  }
  setView('globe'); animate();
  window.__geo={scene,camera,renderer,setView};
}
</script>
</body>
</html>
"""


def build_html(target, ip, geo, scan=None, specs=None, self_geo=None, inline_three=False):
    data = {
        "target": target, "ip": ip,
        "geo": geo or {"ok": False, "message": "no data"},
        "self": self_geo or {"ok": False},
        "scan": scan or {},
        "specs": specs or {},
    }
    html = _HTML.replace("__DATA_JSON__", json.dumps(data))
    html = html.replace("__THREE_CDN__", THREE_CDN)
    html = html.replace("__TARGET__", str(target))
    if inline_three and os.path.isfile(VENDOR_THREE):
        with open(VENDOR_THREE, encoding="utf-8", errors="replace") as f:
            html = html.replace('<script src="three.min.js"></script>',
                                "<script>" + f.read() + "</script>", 1)
    return html


def open_geo_view(target, ip, geo, scan=None, specs=None, self_geo=None):
    out_dir = os.path.join(tempfile.gettempdir(), "portscanner_3d")
    os.makedirs(out_dir, exist_ok=True)
    local_three = os.path.join(out_dir, "three.min.js")
    if os.path.isfile(VENDOR_THREE):
        if not os.path.isfile(local_three) or os.path.getsize(local_three) != os.path.getsize(VENDOR_THREE):
            shutil.copyfile(VENDOR_THREE, local_three)
    path = os.path.join(out_dir, "geo_view.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(target, ip, geo, scan, specs, self_geo))
    webbrowser.open(f"file:///{path.replace(os.sep, '/')}")
    return path
