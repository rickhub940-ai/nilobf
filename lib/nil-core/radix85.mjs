import {randomInt} from 'node:crypto';

export function randomRadix85Alphabet(){const chars=Array.from({length:85},(_,i)=>String.fromCharCode(i+33));for(let i=chars.length-1;i>0;i--){const j=randomInt(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}return chars.join('');}
function validateAlphabet(alphabet){if(typeof alphabet!=='string'||alphabet.length!==85||new Set(alphabet).size!==85||[...alphabet].some(c=>c.charCodeAt(0)<33||c.charCodeAt(0)>117))throw new TypeError('Invalid radix85 alphabet');}
export function encodeRadix85(bytes,alphabet){validateAlphabet(alphabet);if(!Buffer.isBuffer(bytes))throw new TypeError('Expected bytes');const groups=[];for(let i=0;i<bytes.length;i+=4){let n=0;for(let j=0;j<4;j++)n=n*256+(bytes[i+j]??0);const group=Array(5);for(let j=4;j>=0;j--){group[j]=alphabet[n%85];n=Math.floor(n/85);}groups.push(group.join(''));}return groups.join('');}
export function decodeRadix85(text,alphabet){validateAlphabet(alphabet);if(typeof text!=='string'||text.length%5!==0)throw new TypeError('Invalid radix85 length');const lookup=new Map([...alphabet].map((c,i)=>[c,i])),bytes=Buffer.alloc(text.length/5*4);for(let i=0;i<text.length;i+=5){let n=0;for(let j=0;j<5;j++){const v=lookup.get(text[i+j]);if(v===undefined)throw new TypeError('Invalid radix85 digit');n=n*85+v;}if(n>0xffffffff)throw new RangeError('Radix85 integer overflow');bytes.writeUInt32BE(n,i/5*4);}return bytes;}
export function decodeRadix85Container(text,alphabet){const bytes=decodeRadix85(text,alphabet);if(bytes.length<40)throw new RangeError('Invalid packed container');const size=bytes.readUInt32LE(32)+40;if(size>bytes.length||bytes.length-size>3||bytes.subarray(size).some(n=>n!==0))throw new RangeError('Invalid radix85 padding');return bytes.subarray(0,size);}
export function quoteRadix85(text){let equals='=';while((text+']'+equals+']').indexOf(']'+equals+']')!==text.length)equals+='=';return '['+equals+'['+text+']'+equals+']';}

export function radix85Decoder(alphabet,{bufferOutput=false}={}){validateAlphabet(alphabet);if(typeof bufferOutput!=='boolean')throw new TypeError('Invalid radix output mode');return `
if type(data)~='string'or #data<50 or #data%5~=0 or #data>43253810 then invalid()end
local alphabet=${JSON.stringify(alphabet)}
local floor=math.floor
${bufferOutput?`local packedBuffer,packedRead8,packedRead32,packedLength
local packedWord,packedSwap
if type(buffer)=='table'and type(buffer.create)=='function'and type(buffer.writeu32)=='function'and type(buffer.readu32)=='function'and type(buffer.readu8)=='function'and type(buffer.writeu8)=='function'and type(buffer.readstring)=='function'and type(buffer.fromstring)=='function'and type(bit32)=='table'and type(bit32.byteswap)=='function'then
 packedLength=#data/5*4;packedBuffer=buffer.create(packedLength);packedWord,packedSwap,packedRead8,packedRead32=buffer.writeu32,bit32.byteswap,buffer.readu8,buffer.readu32
end`:''}
local lookup={};for i=1,85 do lookup[byte(alphabet,i)]=i-1 end
local output,part={},{}
for i=1,#data,5 do
 local a,b,c,d,e=byte(data,i,i+4)
 a,b,c,d,e=lookup[a],lookup[b],lookup[c],lookup[d],lookup[e]
 if not a or not b or not c or not d or not e then invalid()end
 local n=(((a*85+b)*85+c)*85+d)*85+e
 if n>4294967295 then invalid()end
 ${bufferOutput?'if packedBuffer then packedWord(packedBuffer,(i-1)/5*4,packedSwap(n))else':''}
 part[#part+1]=char(floor(n/16777216)%256,floor(n/65536)%256,floor(n/256)%256,n%256)
 if #part>=1024 then output[#output+1]=concat(part);part={}end
 ${bufferOutput?'end':''}
end
${bufferOutput?'if not packedBuffer then ':''}output[#output+1]=concat(part);data=concat(output)${bufferOutput?' end':''}
`;}
