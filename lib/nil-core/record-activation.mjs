// Small record-level feedback envelopes. The caller supplies the instruction
// key reached by transfer, context and PC. This is reversible obfuscation, not
// a cipher or authentication mechanism. Widths and plaintext stamp stay intact.
export function sealRecord(record,key,pc,ctx,mix,prototypeId){
 const base=prototypeId===undefined?mix(key,ctx.guard):mix(mix(mix(key,prototypeId),pc),ctx.guard);
 const out=Buffer.from(record);let state=mix(base,pc);
 for(let at=0;at<out.length;at+=4){
  state=mix(state,ctx.domains[at/4%9]);
  let plain=0;
  for(let j=0;j<4&&at+j<out.length;j++){
   plain+=record[at+j]*256**j;
   out[at+j]=(record[at+j]+Math.floor(state/256**j))%256;
  }
  state=mix(state,plain);
 }return out;
}

export const recordActivation=String.raw`
  local width=p.reader8(offset-1)
  if width<6 or width>45 then invalid()end
  local view=frame.activation
  if not view then
   local bytes={};view={bytes=bytes}
   view.read8=function(at)local value=bytes[at-view.offset+1];if value==nil then invalid()end;return value end
   view.read32=function(at)return view.read8(at)+view.read8(at+1)*256+view.read8(at+2)*65536+view.read8(at+3)*16777216 end
   frame.activation=view
  end
  if view.offset~=nil then invalid()end;view.offset=offset
  local state=mix(mix(key,ctx.guard),frame.cursor);local active=view.bytes
  for at=0,width-1,4 do
   state=mix(state,ctx.domains[(at/4)%9+1]);local plain=0
   for j=0,3 do
    if at+j<width then
     local value=(p.reader8(offset+at+j)-floor(state/256^j))%256
     active[at+j+1]=value;plain=plain+value*256^j
    end
   end
   state=mix(state,plain)
  end
  local active8,active32=view.read8,view.read32
`;
