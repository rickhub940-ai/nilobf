// Best-effort cleanup of wrapper-owned mutable buffers. This cannot revoke a
// string already copied by the native compiler or by a hook on that compiler.
export const nativeLifetimeRuntime=`
local nativeFill=type(buffer)=='table'and type(buffer.fill)=='function'and buffer.fill or nil
local nativeWriteByte=type(buffer)=='table'and type(buffer.writeu8)=='function'and buffer.writeu8 or nil
local function clearNativeBuffer(data,offset,length)
 if nativeFill then nativeFill(data,offset,0,length)
 elseif nativeWriteByte then for i=offset,offset+length-1 do nativeWriteByte(data,i,0)end
 else invalid()end
end
local function clearNativePieces(pieces)for key in pairs(pieces)do pieces[key]=nil end end
`;

// Selected only after the wrapper's required buffer/bit32 guard. No per-byte
// fallback or duplicated primitive discovery is needed in this dialect.
export const nativeBufferLifetimeRuntime=`
local function clearNativeBuffer(data,offset,length)buffer.fill(data,offset,0,length)end
local function clearNativePieces(pieces)for key in pairs(pieces)do pieces[key]=nil end end
`;
