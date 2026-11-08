import {readFileSync} from 'node:fs';
import {encodeNativeEntropy} from './native-entropy.mjs';

// Split the LZ4 grammar, never the user's Lua syntax. Each byte is preserved.
// Controls, literals and the two offset bytes have different distributions.
export function splitNativeBlock(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>16777216)throw new RangeError('Invalid stream block');
 const walk=streams=>{
  const sizes=[0,0,0,0];let at=0;
  const octet=()=>{if(at>=bytes.length)throw new RangeError('Truncated stream block');return bytes[at++];};
  const put=(i,value)=>{if(streams)streams[i][sizes[i]]=value;sizes[i]++;};
  const length=value=>{if(value===15){let extra;do{extra=octet();put(0,extra);value+=extra;}while(extra===255);}return value;};
  while(at<bytes.length){
   const token=octet();put(0,token);const literals=length(token>>4);
   if(at+literals>bytes.length)throw new RangeError('Truncated stream literals');
   if(streams)bytes.copy(streams[1],sizes[1],at,at+literals);sizes[1]+=literals;at+=literals;
   if(at===bytes.length)break;
   put(2,octet());put(3,octet());length(token&15);
  }
  return sizes;
 };
 const sizes=walk(),streams=sizes.map(n=>Buffer.allocUnsafe(n));walk(streams);
 return streams;
}

export function encodeNativeStreams(bytes){
 const streams=splitNativeBlock(bytes),header=Buffer.alloc(40);header.writeUInt32LE(bytes.length,0);
 const parts=streams.map((plain,i)=>{
  const entropy=plain.length?encodeNativeEntropy(plain):undefined;
  const packed=entropy&&entropy.length<plain.length?entropy:plain;
  header[4+i*9]=packed===entropy?1:0;header.writeUInt32LE(plain.length,5+i*9);header.writeUInt32LE(packed.length,9+i*9);
  return packed;
 });
 return Buffer.concat([header,...parts]);
}
export const nativeStreamsRuntime=readFileSync(new URL('./native-entropy-streams.lua',import.meta.url),'utf8');
