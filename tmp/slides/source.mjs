import fs from 'node:fs/promises';
import {FileBlob,PresentationFile} from 'file:///C:/Users/Predator/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs';
const p=await PresentationFile.importPptx(await FileBlob.load('C:/Users/Predator/Downloads/Maso Agent.pptx'));
await fs.writeFile('C:/Projects/Maso/tmp/slides/source-inspect.txt',(await p.inspect({kind:'slide,layout',maxChars:5000})).ndjson);
for(let i=0;i<p.slides.items.length;i++) {const b=await p.export({slide:p.slides.items[i],format:'png',scale:1});await fs.writeFile(`C:/Projects/Maso/tmp/slides/source-${i+1}.png`,new Uint8Array(await b.arrayBuffer()));}
console.log('Rendered',p.slides.items.length);
