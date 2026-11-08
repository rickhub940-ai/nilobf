import {randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
const M=2**32,delta=0x9e3779b9;
// XTEA counter keystream, 32 cycles, little-endian words. This seals owned VM
// pages against the old four-byte known-header mask shortcut. It is not an
// external secret or an authentication boundary against the executing host.
export function entryForGate(key){if(!Buffer.isBuffer(key)||key.length!==16)throw new TypeError('Invalid page gate');return key.readUInt32LE(0)%(M-1)+1;}
export function sampleGate(bytes,state){
 if(!bytes.length||!Number.isInteger(state)||state<0||state>=M)throw new TypeError('Invalid gate source');
 const cursor=state,values=[];
 for(let i=0;i<16;i++){const value=bytes[(cursor+i*997)%bytes.length];state=((state+value+i*4271)%M*65599+Math.floor(state/65536)*257)%M;values.push((value+Math.floor(state/256**(i%4)))%256);}
 return Buffer.from(values);
}
export function xteaBlock(low,high,key){
 let sum=0;for(let i=0;i<32;i++){
  low=(low+((((((high<<4)^(high>>>5))>>>0)+high)>>>0)^((sum+key[sum&3])>>>0)>>>0))>>>0;
  sum=(sum+delta)>>>0;
  high=(high+((((((low<<4)^(low>>>5))>>>0)+low)>>>0)^((sum+key[(sum>>>11)&3])>>>0)>>>0))>>>0;
 }return [low,high];
}
export function sealPage(bytes,key,nonce=randomBytes(8)){
 entryForGate(key);if(!Buffer.isBuffer(nonce)||nonce.length!==8)throw new TypeError('Invalid page nonce');
 const words=Array.from({length:4},(_,i)=>key.readUInt32LE(i*4)),out=Buffer.alloc(bytes.length+8),mask=Buffer.alloc(8);nonce.copy(out);
 let low=nonce.readUInt32LE(0),high=nonce.readUInt32LE(4);
 for(let at=0;at<bytes.length;at+=8){const [a,b]=xteaBlock(low,high,words);mask.writeUInt32LE(a,0);mask.writeUInt32LE(b,4);for(let j=0;j<8&&at+j<bytes.length;j++)out[at+j+8]=bytes[at+j]^mask[j];low=(low+1)>>>0;if(low===0)high=(high+1)>>>0;}
 return out;
}
export function sealedPageRuntime({fastCipher=false,nativeCipher=false}={}){
 if(typeof fastCipher!=='boolean')throw new TypeError('Invalid cipher arithmetic mode');
 if(typeof nativeCipher!=='boolean'||nativeCipher&&!fastCipher)throw new TypeError('Native cipher requires fast arithmetic mode');
 if(nativeCipher)return readFileSync(new URL('./sealed-pages-native.lua',import.meta.url),'utf8');
 let source=readFileSync(new URL('./sealed-pages.lua',import.meta.url),'utf8');
 if(!fastCipher)return source;
 // Only the native bit32 path may defer wrapping. Intermediate a/b values
 // are exact integers below 33*2^32; each shift/XOR observes their low word.
 // The portable arithmetic/byte tail still receives explicitly wrapped words.
 const start=source.indexOf('  if shiftLeft and shiftRight then for round=1,32 do'),end=source.indexOf('  end else for round=1,32 do',start);
 if(start<0||end<start)throw new Error('Cipher arithmetic anchors changed');
 const fast=`  if nativeWords then for round=1,32 do
   a=a+bxor(bxor(shiftLeft(b,4),shiftRight(b,5))+b,leftRounds[round])
   b=b+bxor(bxor(shiftLeft(a,4),shiftRight(a,5))+a,rightRounds[round])
  end;a=a%modulus;b=b%modulus
  elseif shiftLeft and shiftRight then for round=1,32 do
   a=(a+bxor((bxor(shiftLeft(b,4),shiftRight(b,5))+b)%modulus,leftRounds[round]))%modulus
   b=(b+bxor((bxor(shiftLeft(a,4),shiftRight(a,5))+a)%modulus,rightRounds[round]))%modulus
`;
 source=source.slice(0,start)+fast+source.slice(end);
 const anchor='local pageWrite32=';
 const guard=`local nativeWords=false
if bxor and shiftLeft and shiftRight then
 local ok,valid=pcall(function()local n=137438953471;return bxor(n,0)==4294967295 and shiftLeft(n,4)==4294967280 and shiftRight(n,5)==134217727 end)
 nativeWords=ok and valid
end
`;
 return source.replace(anchor,guard+anchor);
}
