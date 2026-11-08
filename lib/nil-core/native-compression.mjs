import {readFileSync} from 'node:fs';
import {parseNativeBlock} from './native-compression-parse.mjs';
import {encodeNativeEntropy} from './native-entropy.mjs';
import {encodeNativeStreams} from './native-entropy-streams.mjs';

// Independent LZ4 block encoder. Native Lua remains opaque bytes, never AST.
// Format: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
export function encodeNativeBlock(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>16777216)throw new RangeError('Invalid native block');
 const output=Buffer.allocUnsafe(bytes.length+Math.ceil(bytes.length/255)+16);
 const dictionary=new Int32Array(65536);dictionary.fill(-1);
 const previousPositions=new Int32Array(65536);previousPositions.fill(-1);
 let cursor=0,anchor=0,at=0;
 const extension=length=>{while(length>=255){output[cursor++]=255;length-=255;}output[cursor++]=length;};
 const sequence=(start,end,offset,length)=>{
  const literals=end-start,match=length?length-4:0;
  output[cursor++]=(Math.min(literals,15)<<4)|Math.min(match,15);
  if(literals>=15)extension(literals-15);
  bytes.copy(output,cursor,start,end);cursor+=literals;
  if(length){output.writeUInt16LE(offset,cursor);cursor+=2;if(match>=15)extension(match-15);}
 };
 const remember=(position,first=bytes.readUInt32LE(position))=>{const slot=Math.imul(first,0x9e3779b1)>>>16,previous=dictionary[slot];previousPositions[position&65535]=previous;dictionary[slot]=position;return previous;};
 while(at<=bytes.length-12){
  const first=bytes.readUInt32LE(at);
  let candidate=remember(at,first),best=-1,length=0;
  // Bounded search improves ratio without increasing decoder work or storage.
  for(let depth=0;depth<32&&candidate>=0&&at-candidate<=65535;depth++){
   // A candidate that differs at the current best length cannot beat it.
   // This prunes repeated prefix walks without changing greedy selection.
   if(bytes.readUInt32LE(candidate)===first&&(!length||bytes[candidate+length]===bytes[at+length])){
    let matched=4;while(at+matched<bytes.length-5&&bytes[candidate+matched]===bytes[at+matched])matched++;
    if(matched>length){length=matched;best=candidate;if(at+length===bytes.length-5)break;}
   }
   candidate=previousPositions[candidate&65535];
  }
  if(best<0){at++;continue;}
  sequence(anchor,at,at-best,length);
  const stop=at+length;for(let position=at+1;position<stop&&position<=bytes.length-12;position++)remember(position);
  at=stop;anchor=stop;
 }
 sequence(anchor,bytes.length,0,0);
 return Buffer.from(output.subarray(0,cursor));
}

// Small inputs and incompressible blocks retain the original representation.
 // Reserve 16 KiB for decoder/presentation overhead before accepting a region.
export function compressNativeBytes(bytes,{mode='greedy',entropyCoding=false,entropyStreams=false}={}){
 if(!['greedy','balanced'].includes(mode))throw new TypeError('Invalid compression mode');
 if(typeof entropyStreams!=='boolean'||entropyStreams&&!entropyCoding)throw new TypeError('Stream entropy requires entropy coding');
 if(typeof entropyCoding!=='boolean')throw new TypeError('Invalid entropy coding mode');
 const greedy=encodeNativeBlock(bytes),parsed=mode==='balanced'?parseNativeBlock(bytes):undefined;
 const encoded=parsed&&parsed.length<greedy.length?parsed:greedy;
 const metrics={parser:encoded===parsed?'cost-aware':'greedy',greedyBytes:greedy.length,lz4Bytes:encoded.length,parseSavedBytes:greedy.length-encoded.length,entropySavedBytes:0};
 if(encoded.length+16384>=bytes.length)return {bytes,decodedSize:bytes.length,codec:0,...metrics,parseSavedBytes:0};
 const entropy=entropyCoding?encodeNativeEntropy(encoded):undefined;
 const streams=entropyStreams?encodeNativeStreams(encoded):undefined;
 const baseline=entropy&&entropy.length+3072<encoded.length?entropy:encoded;
 const streamBudget=baseline===entropy?2048:6144;
 if(streams&&streams.length+streamBudget<baseline.length)return {bytes:streams,decodedSize:bytes.length,codec:3,...metrics,entropySavedBytes:encoded.length-streams.length,streamSavedBytes:baseline.length-streams.length};
 // Budget extra emitted decoder code, rather than accepting marginal savings.
 if(entropy&&entropy.length+3072<encoded.length)return {bytes:entropy,decodedSize:bytes.length,codec:2,...metrics,entropySavedBytes:encoded.length-entropy.length};
 return {bytes:encoded,decodedSize:bytes.length,codec:1,...metrics};
}
export const nativeBlockRuntime=readFileSync(new URL('./native-compression.lua',import.meta.url),'utf8');
export const nativeBufferBlockRuntime=readFileSync(new URL('./native-compression-buffer.lua',import.meta.url),'utf8');
