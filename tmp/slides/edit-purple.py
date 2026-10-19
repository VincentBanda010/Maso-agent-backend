from pathlib import Path
p=Path('tmp/slides/build-purple.mjs');t=p.read_text(encoding='utf-8-sig')
t=t.replace("const C={ink:'#243A45',green:'#079E8C',muted:'#586772',light:'#E7F6F1',red:'#B3263B'};","const C={ink:'#1A1A2E',green:'#7C3AED',muted:'#616477',light:'#F0EFFE',red:'#B62C43'};\nconst {makeNativeBulletParagraphs}=await import(pathToFileURL(skill+'/container_tools/artifact_tool_utils.mjs').href);\nasync function vector(s,name,x,y,w,h,color=C.green){let svg=await fs.readFile(build+'/vectors/'+name+'.svg','utf8');svg=svg.replaceAll('currentColor',color).replace('stroke-width=\"2\"','stroke-width=\"1.5\"');s.images.add({svg,alt:name==='original-circuit'?'Original circuit pattern preserved from the supplied deck':name+' vector from Lucide',position:{left:x,top:y,width:w,height:h}});}\nfunction bullets(s,items,x,y,w,h,size=26){let a=txt(s,'',x,y,w,h,size);a.text=makeNativeBulletParagraphs(items,{marginLeftPoints:16,hangingPoints:8,spaceAfterPoints:12});a.text.style={typeface:'Century Gothic',fontSize:size,color:C.ink,autoFit:'none'};return a;}")
t=t.replace("typeface:'Arial'","typeface:'Century Gothic'")
a=t.index('async function slide(');b=t.index('\nfunction row(',a)
t=t[:a]+'''async function slide(title,notes='',cover=false){let s=p.slides.add();s.background.fill=cover?'#6D28D9':'#FFFFFF';if(cover){await vector(s,'original-circuit',600,15,350,350,'#9461E8');}else{await vector(s,'original-circuit',806,0,154,154,'#E4D8F8');await vector(s,'original-circuit',0,412,122,122,'#E4D8F8');txt(s,title,62,42,840,66,40,C.green,true);txt(s,String(p.slides.items.length).padStart(2,'0'),870,505,40,20,14,C.green);}s.speakerNotes.text=notes+'\\n\\nVisual sources: original circuit path preserved from C:/Users/Predator/Downloads/Maso Agent.pptx. Lucide vector icons from https://github.com/lucide-icons/lucide/tree/main/icons under the ISC license. Purple #7C3AED, deep purple #6D28D9, pale lavender #F0EFFE and ink #1A1A2E match the application styles in C:/Projects/MasoFront/src/App.css. Typeface requested by the user: Century Gothic. Product claims checked against the code on 19 October 2026.';return s;}'''+t[b:]
t=t.replace('745,36,27','630,36,27').replace('745,54,23','630,54,23')
# Add visual assets before export, leaving source content editable.
idx=t.index("await fs.mkdir(build+'/final-previews'")
t=t[:idx]+'''
// Supporting vector visuals use source artwork and official Lucide assets.
for(const index of [0,13]){
 const sl=p.slides.items[index];
 for(const sh of sl.shapes.items){sh.text.style={...sh.text.style,color:'#FFFFFF'};}
 await vector(sl,'shield-check',660,270,200,200,'#FFFFFF');
}
await vector(p.slides.items[1],'message-circle-warning',765,170,125,125);
await vector(p.slides.items[3],'users',790,180,110,110);
await vector(p.slides.items[5],'scan-line',790,180,110,110);
await vector(p.slides.items[6],'brain-circuit',370,140,54,54);
await vector(p.slides.items[6],'link',810,140,54,54);
await vector(p.slides.items[7],'list-checks',785,265,110,110);
await vector(p.slides.items[8],'shield-check',780,145,100,100,C.red);
await vector(p.slides.items[9],'lock-keyhole',790,180,110,110);
await vector(p.slides.items[10],'circle-check',785,145,110,110);
await vector(p.slides.items[11],'presentation',790,180,110,110);
await vector(p.slides.items[12],'chart-no-axes-combined',790,180,110,110);
''' +t[idx:]
# Tighten text to make room for purposeful visuals.
t=t.replace('70,145,830,175,40','70,145,660,175,37')
t=t.replace('Checks message and email text','Checks messages\\nand email text').replace('Checks the written web address','Checks written\\nweb addresses')
t=t.replace('Maso downloads the reported-link list','Maso downloads reported links').replace('Your link is compared locally','Maso compares your link locally')
t=t.replace("txt(s,'Reported test link detected\\nNormal control link returned no feed match\\nAI and OpenPhish completed through the public demo link',70,324,820,135,27,C.ink);","bullets(s,['Reported test link detected','Normal link returned no OpenPhish match','AI and OpenPhish worked through the public demo'],70,324,815,145,25);")
t=t.replace('final-previews','purple-previews').replace("build+'/candidate.pptx'","build+'/purple-candidate.pptx'").replace('Maso-Competition-Pitch.pptx','Maso-Competition-Pitch-Purple.pptx').replace("families:['Arial']","families:['Century Gothic']").replace("basis:'design'","basis:'user_request'").replace("build+'/validation.json'","build+'/purple-validation.json'")
p.write_text(t,encoding='utf-8')
