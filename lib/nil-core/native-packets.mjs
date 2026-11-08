import { randomInt } from 'node:crypto';
import { LIMITS } from './opcodes.mjs';
import {nativeLifetimeRuntime} from './native-lifetime.mjs';
import {planPacketLayout} from './packet-layout.mjs';
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};

// Native chunks are deliberately not parsed or transpiled. Store shuffled,
// independently masked packets, and reconstruct only at the native boundary.
// Keys travel with the decoder: this adds representation diversity, not secrecy
// from the runtime owner or cryptographic authentication.
export function packNativePackets(bytes, packetLayout) {
  if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>LIMITS.blobBytes)throw new TypeError('Invalid native bytes');
  const ranges=packetLayout===undefined?undefined:planPacketLayout(bytes.length,packetLayout).ranges;
  const packets=[];let packetIndex=0;
  for(let offset=0;offset<bytes.length;){
    const length=ranges?ranges[packetIndex++].length:Math.min(randomInt(4096,8193),bytes.length-offset);
    const seed=randomInt(65536),multiplier=randomInt(5000,32768)*2+1,increment=randomInt(32768)*2+1,reverse=randomInt(2);
    let state=seed;const data=Buffer.allocUnsafe(length);
    for(let j=0;j<length;j++){
      state=(state*multiplier+increment)%65536;
      const slot=reverse ? length-j-1 : j;
      data[slot]=(bytes[offset+j]+Math.floor(state/256))%256;
    }
    packets.push(Buffer.concat([u32(offset),u32(length),u32(seed),u32(multiplier),u32(increment),Buffer.from([reverse]),data]));
    offset+=length;
  }
  for(let i=packets.length-1;i>0;i--){const j=randomInt(i+1);[packets[i],packets[j]]=[packets[j],packets[i]];}
  return Buffer.concat([u32(bytes.length),u32(packets.length),...packets]);
}

export const nativePacketDecoder = `
${nativeLifetimeRuntime}
local function nativeBody(frame)
 local pos=1
 local function take(n)if n<0 or pos+n-1>#frame then invalid()end;local s=sub(frame,pos,pos+n-1);pos=pos+n;return s end
 local function word()local s=take(4);local a,b,c,d=byte(s,1,4);return a+b*256+c*65536+d*16777216 end
 local size,count=word(),word()
 if size<1 or size>16777216 or count<1 or count>4096 then invalid()end
 local packets={}
 for i=1,count do
  local offset,length,seed,multiplier,increment=word(),word(),word(),word(),word()
  local reverse=byte(take(1))
  if length<1 or length>8192 or offset+length>size or seed>65535 or multiplier<1 or multiplier>65535 or multiplier%2~=1 or increment<1 or increment>65535 or increment%2~=1 or reverse>1 then invalid()end
  packets[i]={offset,length,seed,multiplier,increment,reverse,take(length)}
 end
 if pos~=#frame+1 then invalid()end
 table.sort(packets,function(a,b)return a[1]<b[1]end)
 local binary=type(buffer)=='table'and type(buffer.fromstring)=='function'and type(buffer.create)=='function'and type(buffer.readu8)=='function'and type(buffer.writeu8)=='function'and type(buffer.tostring)=='function'
 local binaryFrom,binaryRead,binaryWrite,binaryString,decoded
 if binary then binaryFrom,binaryRead,binaryWrite,binaryString=buffer.fromstring,buffer.readu8,buffer.writeu8,buffer.tostring;decoded=buffer.create(size)end
 local floor=math.floor
 local output,nextOffset={},0
 for _,packet in ipairs(packets)do
  if packet[1]~=nextOffset then invalid()end
  local length,state,multiplier,increment,reverse,encoded=packet[2],packet[3],packet[4],packet[5],packet[6],packet[7]
  if binary then encoded=binaryFrom(encoded)end
  local block={}
  for j=1,length do
   state=(state*multiplier+increment)%65536
   local slot=reverse==1 and length-j+1 or j
   local value=((binary and binaryRead(encoded,slot-1)or byte(encoded,slot))-floor(state/256))%256
   if binary then binaryWrite(decoded,nextOffset+j-1,value)else block[j]=char(value)end
  end
  if not binary then output[#output+1]=concat(block)end;nextOffset=nextOffset+length
 end
 if nextOffset~=size then invalid()end
 local source=binary and binaryString(decoded)or concat(output)
 if binary then clearNativeBuffer(decoded,0,size)end
 clearNativePieces(output);clearNativePieces(packets)
 decoded,output,packets=nil,nil,nil
 return source
end
`;
