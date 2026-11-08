// Sealed records never enter the decoded cache. Specialize that known mode
// after directory insertion so fetch keeps scalar aliases instead of allocating
// a one-entry records table and a record descriptor on every VM instruction.
export function specializeSealedFetch(source){
 source=source.replaceAll('\r\n','\n');
 const start=source.indexOf('local function open(frame');
 const tail=/  return (?:record\.handler|dispatchHandler)\n end/.exec(source.slice(start));
 if(start<0||!tail)throw new Error('Sealed fetch function boundary changed');
 const end=start+tail.index+tail[0].length;
 let body=source.slice(start,end);
 const cache='  local records={}\n  local record=records[frame.bank]\n  if record and record.key~=key then invalid()end\n  if not record then';
 const descriptor='  record={key=key,masks=masks,encoded=encoded,slot=slot,handler=handler,raw=raw,semantic=semantic,stamp=stamp};records[frame.bank]=record\n  end';
 if(!body.includes(cache)||!body.includes(descriptor))throw new Error('Sealed fetch specialization contract changed');
 body=body.replace(cache,'').replace(descriptor,'  local recordMasks,recordEncoded,recordSlot,recordHandler,recordRaw,recordSemantic,recordStamp=masks,encoded,slot,handler,raw,semantic,stamp');
 const names={masks:'recordMasks',encoded:'recordEncoded',slot:'recordSlot',handler:'recordHandler',raw:'recordRaw',semantic:'recordSemantic',stamp:'recordStamp'};
 body=body.replace(/\brecord\.(masks|encoded|slot|handler|raw|semantic|stamp)\b/g,(_,field)=>names[field]);
 if(/\brecord\b|\brecords\b/.test(body))throw new Error('Unhandled sealed record reference');
 source=source.slice(0,start)+body+source.slice(end);
 return source.replace('raw={},maskCache={},records={}','raw={}');
}
