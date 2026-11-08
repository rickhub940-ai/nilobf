// Two coupled feedback lanes over an existing record. No seed/header or tag
// bytes are added. This is reversible VM encoding, not a secret-key cipher.
const rotl=(n,r)=>(n<<r|n>>>(32-r))>>>0;
const rotr=(n,r)=>(n>>>r|n<<(32-r))>>>0;
const xor=(a,b)=>(a^b)>>>0;

export function sealLaneRecord(record,key,pc,ctx,mix,prototypeId){
 if(!Buffer.isBuffer(record)||record.length<6||record.length>45||!Number.isInteger(prototypeId)||prototypeId<1)throw new TypeError('Invalid lane record');
 const width=record.length,base=mix(mix(mix(key,prototypeId),pc),ctx.guard);
 let a=mix(base,pc),b=mix(base,width);
 const out=Buffer.allocUnsafe(width);
 for(let at=0;at<width;at+=4){
  const bytes=Math.min(4,width-at),bits=bytes*8,ordinal=at/4+1;
  a=mix(a,ctx.domains[(a+b+ordinal)%9]);
  const mask=xor(a,rotl(b,ordinal)),rotation=(a+b)%bits;
  const plain=record.readUIntLE(at,bytes),masked=xor(plain,mask)%2**bits;
  const encoded=bits===32?rotr(masked,rotation):Math.floor(masked/2**rotation)+(masked%2**rotation)*2**(bits-rotation);
  out.writeUIntLE(encoded,at,bytes);
  const next=mix(a,plain);a=b;b=next;
 }
 return out;
}

export const laneBufferActivation=String.raw`
  local width=p.reader8(offset-1)
  if width<6 or width>45 then invalid()end
  local view=frame.activation
  if not view then
   view={storage=buffer.create(48),length=0}
   frame.activation=view
  end
  if view.offset~=nil or view.length~=0 then invalid()end
  view.offset,view.length=offset,width
  local base=mix(key,ctx.guard)
  local a,b=mix(base,frame.cursor),mix(base,width)
  local active=view.storage;local bxor,lrotate=bit32.bxor,bit32.lrotate
  for at=0,width-1,4 do
   local bytes=math.min(4,width-at);local bits,ordinal=bytes*8,at/4+1
   a=mix(a,ctx.domains[(a+b+ordinal)%9+1])
   local mask=bxor(a,lrotate(b,ordinal));local rotation=(a+b)%bits
   local encoded,plain
   if bytes==4 then
    encoded=p.reader32(offset+at);plain=bxor(lrotate(encoded,rotation),mask)
    buffer.writeu32(active,at,plain)
   else
    encoded=0;for j=0,bytes-1 do encoded=encoded+p.reader8(offset+at+j)*256^j end
    local left=bits-rotation
    plain=bxor(floor(encoded/2^left)+(encoded%2^left)*2^rotation,mask)%2^bits
    buffer.writebits(active,at*8,bits,plain)
   end
   a,b=b,mix(a,plain)
  end
`;

export const retireLaneBuffer='  buffer.fill(active,0,0,48);view.offset=nil;view.length=0\n';

// Every odd square is 1 mod 8. Two Newton steps lift this inverse through
// six to at least eight correct low bits, replacing the three steps from 1.
export const byteInverse=' local function inverse(odd)local result=odd;for i=1,2 do result=result*(2-odd*result)%256 end;return result end';

// The keyed bit parser has explicit extent checks before every field and
// stamp read. Read its activation buffer directly instead of crossing reader
// closures and reconstructing bit fields from four/five separate byte reads.
export function specializeLaneReads(source){
 const start=source.indexOf('local function open(frame');
 const tail=/  return (?:recordHandler|dispatchHandler)\n end/.exec(source.slice(start));
 if(start<0||!tail)throw new Error('Lane fetch boundary changed');
 const end=start+tail.index+tail[0].length;
 let body=source.slice(start,end);
 const edits=[
  ['  local bitReader,wordReader=active8,active32\n',''],
  ['packedBits(bitReader,bitBase,bitCursor,width,wordReader)','buffer.readbits(active,(bitBase-offset)*8+bitCursor,width)'],
  ['  packedTail(bitReader,bitBase,bitCursor)','  local used=bitCursor%8;if used~=0 and buffer.readbits(active,(bitBase-offset)*8+bitCursor,8-used)~=0 then invalid()end'],
  ['active8(offset+1)','buffer.readu8(active,1)'],
  ['active8(offset)','buffer.readu8(active,0)'],
  ['active32(position)','buffer.readu32(active,position-offset)']
 ];
 for(const [before,after]of edits){if(!body.includes(before))throw new Error('Lane bit reader contract changed: '+before);body=body.replaceAll(before,after);}
 if(/\b(active8|active32|bitReader|wordReader)\b/.test(body))throw new Error('Unhandled lane reader reference');
 body=body.replaceAll('invalid()','rejectActivation(frame)');
 const reject=String.raw`local function rejectActivation(frame)
  local view=frame.activation
  if view then buffer.fill(view.storage,0,0,48);view.offset=nil;view.length=0 end
  invalid()
 end
 `;
 return source.slice(0,start)+reject+body+source.slice(end);
}
