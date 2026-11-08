-- Nil v2/v3 runtime factory. V3 keeps instructions encoded between steps.
-- Environment capabilities come from the host; this interpreter is not a sandbox.
return function(blob, environment, maxSteps)
    local byte, sub = string.byte, string.sub
    local unpackValues = table.unpack or unpack
    local function pack(...) return { n = select('#', ...), ... } end
    local function invalid() error('Nil invalid bytecode', 0) end
    if type(blob) ~= 'string' or #blob > 16777216 or
       sub(blob, 1, 4) ~= 'STBC' or (byte(blob,5) ~= 2 and byte(blob,5) ~= 3) or type(environment) ~= 'table' or
       type(maxSteps) ~= 'number' or maxSteps < 1 or maxSteps > 1000000000 or maxSteps % 1 ~= 0 then
        invalid()
    end
    local protected = byte(blob,5) == 3
    local position = 6
    local function need(count)
        if count < 0 or position + count - 1 > #blob then invalid() end
    end
    local function u8()
        need(1)
        local value = byte(blob, position)
        position = position + 1
        return value
    end
    local function u32()
        need(4)
        local a,b,c,d = byte(blob, position, position + 3)
        position = position + 4
        return a + b * 256 + c * 65536 + d * 16777216
    end
    local function bytes()
        local length = u32()
        need(length)
        local value = sub(blob, position, position + length - 1)
        position = position + length
        return value
    end
    local function constant(p, slot, remember)
        local tag = p.tags[slot]
        if tag == 0 then return nil elseif tag == 1 then return false elseif tag == 2 then return true end
        local encoded = p.constantData[slot]
        if type(encoded) ~= 'string' then invalid() end
        local parts, block = {}, {}
        for j = 1, #encoded do
            block[#block+1] = string.char((byte(encoded,j)-p.seedA-slot*p.seedB-j*(p.seedA%251+1))%256)
            if #block == 4096 then parts[#parts+1]=table.concat(block);block={}end
        end
        parts[#parts+1] = table.concat(block)
        local value = table.concat(parts)
        if tag == 3 then
            value = tonumber(value)
            if not value or value ~= value or value == math.huge or value == -math.huge then invalid()end
            if remember then rawset(p.constants,slot,value)end
        end
        return value
    end
    local function instructionReader(p)
        local code = p.code
        if not protected then return function(pc)return code[pc],code[pc+1],code[pc+2],code[pc+3],code[pc+4]end end
        local seedA,seedB=p.seedA,p.seedB
        local oa,ob,oc,od=p.order[1],p.order[2],p.order[3],p.order[4]
        local stride=(seedA*seedB+seedB*257)%4294967296
        return function(pc)
            local i=(pc-1)/5+1;local base=seedA*i
            return (code[pc]-seedA-i*seedB)%256,
                (code[pc+oa]-base-stride)%4294967296,
                (code[pc+ob]-base-2*stride)%4294967296,
                (code[pc+oc]-base-3*stride)%4294967296,
                (code[pc+od]-base-4*stride)%4294967296
        end
    end
    local count, entry = u32(), u32()
    if count < 1 or count > 4096 or entry < 1 or entry > count then invalid() end
    local prototypes, totalInstructions, totalConstants = {}, 0, 0
    for id = 1, count do
        local p = {}
        p.parent, p.parameters, p.vararg = u32(), u32(), u8()
        p.registers, p.cells = u32(), u32()
        if p.parent > count or p.parent >= id or p.vararg > 1 or p.registers > 65535 or
           p.cells > 8192 or p.parameters > p.cells then invalid() end
        p.upCount = u32()
        if p.upCount > 8192 then invalid() end
        p.up = {}
        for i = 1, p.upCount do
            local kind, slot = u8(), u32()
            if kind > 1 or slot < 1 then invalid() end
            p.up[i] = { kind, slot }
        end
        if protected then
            p.seedA,p.seedB = u32(),u32()
            if p.seedA<1 or p.seedA>65535 or p.seedB<1 or p.seedB>65535 then invalid()end
            p.order = {};local seen={}
            for i=1,4 do local slot=u8();if slot<1 or slot>4 or seen[slot]then invalid()end;p.order[i]=slot;seen[slot]=true end
            p.opLast=u8();if p.opLast>1 then invalid()end
        end
        p.constantCount = u32()
        totalConstants = totalConstants + p.constantCount
        if totalConstants > 65536 then invalid() end
        p.constants, p.tags, p.constantData = {}, {}, {}
        for i = 1, p.constantCount do
            local tag = u8()
            p.tags[i] = tag
            if protected then
                if tag == 3 or tag == 4 then p.constantData[i] = bytes()
                elseif tag>4 then invalid()end
                if tag == 3 then constant(p,i)end
            elseif tag == 1 then p.constants[i] = false
            elseif tag == 2 then p.constants[i] = true
            elseif tag == 3 then
                local value = tonumber(bytes())
                if not value or value ~= value or value == math.huge or value == -math.huge then invalid() end
                p.constants[i] = value
            elseif tag == 4 then p.constants[i] = bytes()
            elseif tag ~= 0 then invalid() end
        end
        if protected then
            local captured=p
            p.constants=setmetatable({}, {__index=function(_,slot)return constant(captured,slot,true)end})
        end
        p.instructionCount = u32()
        totalInstructions = totalInstructions + p.instructionCount
        if p.instructionCount < 1 or totalInstructions > 100000 then invalid() end
        need(p.instructionCount * 17)
        p.code = {}
        local offset = 1
        for i = 1, p.instructionCount do
            if not protected or p.opLast==0 then p.code[offset] = u8()end
            p.code[offset+1],p.code[offset+2],p.code[offset+3],p.code[offset+4] = u32(),u32(),u32(),u32()
            if protected and p.opLast==1 then p.code[offset]=u8()end
            offset = offset + 5
        end
        p.readInstruction=instructionReader(p)
        prototypes[id] = p
    end
    if position ~= #blob + 1 or prototypes[entry].parent ~= 0 then invalid() end
    local roles = {
        {'r','k'}, {'r','g'}, {'r','g'}, {'r','l'}, {'l','r'}, {'l','r'},
        {'r','u'}, {'u','r'}, {'r','r'}, {'r','r','r'}, {'r','r','r'},
        {'r'}, {'r'}, {'r','r'}, {'r','r'}, {'r','r','i'}, {'r','r','r'},
        {'r'}, {'r'}, {'j'}, {'r','j'}, {'r','j'}, {'r','j'}, {'r','p'},
        {'r','r','a'}, {'r','r','r','b'}, {'r','r','i'}, {'r','r','r'},
        {'r','r','r','j'}, {'r','r','j'}, {'r','r'}, {'r','r','r'}, {'r','r'},
        {'r','k','r','k'}, {'r','k','l'}, {'r','k','l'}, {'r','k','r','r'}, {'r','l','r','r'},
    }
    for id = 1, count do
        local p = prototypes[id]
        if id ~= entry and p.parent == 0 then invalid() end
        for i = 1, p.upCount do
            local descriptor, parent = p.up[i], prototypes[p.parent]
            if not parent or descriptor[2] > (descriptor[1] == 0 and parent.cells or parent.upCount) then invalid() end
        end
        local code = p.code
        for pc = 1, #code, 5 do
            local op,a,b,c,d = p.readInstruction(pc)
            local role = roles[op]
            if not role or (op == 18 and p.vararg ~= 1) then invalid() end
            local values={a,b,c,d}
            for field = 1, 4 do
                local value, kind = values[field], role[field]
                if not kind then if value ~= 0 then invalid() end
                elseif kind == 'r' then if value < 1 or value > p.registers then invalid() end
                elseif kind == 'k' or kind == 'g' then
                    if value < 1 or value > p.constantCount or (kind == 'g' and p.tags[value] ~= 4) then invalid() end
                elseif kind == 'l' then if value < 1 or value > p.cells then invalid() end
                elseif kind == 'u' then if value < 1 or value > p.upCount then invalid() end
                elseif kind == 'j' then if value < 1 or value > #code or value % 5 ~= 1 then invalid() end
                elseif kind == 'i' then if value < 1 or value > 100000 then invalid() end
                elseif kind == 'a' then if value < 1 or value > 3 then invalid() end
                elseif kind == 'b' then if value < 1 or value > 13 then invalid() end
                elseif kind == 'p' then
                    if value < 1 or value > count or prototypes[value].parent ~= id then invalid() end
                end
            end
        end
    end
    -- Decode and validate once. Dispatch only touches predecoded numeric arrays.
    local remaining, make = maxSteps, nil
    make = function(id, upvalues)
        local prototype = prototypes[id]
        return function(...)
            local args, registers, cells = pack(...), {}, {}
            for i = 1, prototype.parameters do cells[i] = { v = args[i] } end
            local varargs = { n = 0 }
            if prototype.vararg == 1 then
                for i = prototype.parameters + 1, args.n do
                    varargs.n = varargs.n + 1
                    varargs[varargs.n] = args[i]
                end
            end
            local code, constants, pc = prototype.code, prototype.constants, 1
            local readInstruction=prototype.readInstruction
            while true do
                remaining = remaining - 1
                if remaining < 0 then error('Nil instruction budget exceeded', 0) end
                local op,a,b,c,d = readInstruction(pc)
                pc = pc + 5
                if op == 1 then registers[a] = constants[b]
                elseif op == 2 then registers[a] = environment[constants[b]]
                elseif op == 3 then environment[constants[b]] = registers[a]
                elseif op == 4 then registers[a] = cells[b].v
                elseif op == 5 then cells[a].v = registers[b]
                elseif op == 6 then cells[a] = { v = registers[b] }
                elseif op == 7 then registers[a] = upvalues[b].v
                elseif op == 8 then upvalues[a].v = registers[b]
                elseif op == 9 then registers[a] = registers[b]
                elseif op == 10 then registers[a] = registers[b][registers[c]]
                elseif op == 11 then registers[a][registers[b]] = registers[c]
                elseif op == 12 then registers[a] = {}
                elseif op == 13 then registers[a] = { n = 0 }
                elseif op == 14 then
                    local tuple = registers[a]
                    tuple.n = tuple.n + 1; tuple[tuple.n] = registers[b]
                elseif op == 15 then
                    local tuple, values = registers[a], registers[b]
                    local base = tuple.n
                    for i = 1, values.n do tuple[base+i] = values[i] end
                    tuple.n = base + values.n
                elseif op == 16 then registers[a] = registers[b][c]
                elseif op == 17 then
                    local values = registers[c]
                    registers[a] = pack(registers[b](unpackValues(values, 1, values.n)))
                elseif op == 18 then registers[a] = varargs
                elseif op == 19 then
                    local values = registers[a]; return unpackValues(values, 1, values.n)
                elseif op == 20 then pc = a
                elseif op == 21 then if not registers[a] then pc = b end
                elseif op == 22 then if registers[a] then pc = b end
                elseif op == 23 then if registers[a] == nil then pc = b end
                elseif op == 24 then
                    local child, captured = prototypes[b], {}
                    for i = 1, child.upCount do
                        local descriptor = child.up[i]
                        captured[i] = descriptor[1] == 0 and cells[descriptor[2]] or upvalues[descriptor[2]]
                    end
                    registers[a] = make(b, captured)
                elseif op == 25 then
                    local value = registers[b]
                    if c == 1 then registers[a] = -value
                    elseif c == 2 then registers[a] = not value
                    else registers[a] = #value end
                elseif op == 26 then
                    local left, right = registers[b], registers[c]
                    if d == 1 then registers[a] = left + right
                    elseif d == 2 then registers[a] = left - right
                    elseif d == 3 then registers[a] = left * right
                    elseif d == 4 then registers[a] = left / right
                    elseif d == 5 then registers[a] = left % right
                    elseif d == 6 then registers[a] = left ^ right
                    elseif d == 7 then registers[a] = left .. right
                    elseif d == 8 then registers[a] = left == right
                    elseif d == 9 then registers[a] = left ~= right
                    elseif d == 10 then registers[a] = left < right
                    elseif d == 11 then registers[a] = left <= right
                    elseif d == 12 then registers[a] = left > right
                    else registers[a] = left >= right end
                elseif op == 27 then
                    local target, values = registers[a], registers[b]
                    for i = 1, values.n do target[c+i-1] = values[i] end
                elseif op == 28 then
                    local index, limit, step = tonumber(registers[a]), tonumber(registers[b]), tonumber(registers[c])
                    if not index or not limit or not step then error('Nil numeric for requires numbers', 0) end
                    registers[a],registers[b],registers[c] = index,limit,step
                elseif op == 29 then
                    local index, limit, step = registers[a], registers[b], registers[c]
                    local inRange
                    if step > 0 then inRange = index <= limit else inRange = index >= limit end
                    if not inRange then pc = d end
                elseif op == 30 then registers[a] = registers[a] + registers[b]; pc = c
                elseif op == 31 then
                    local values = registers[b]
                    return registers[a](unpackValues(values, 1, values.n))
                elseif op == 32 then
                    local values = registers[c]
                    registers[a] = registers[b](unpackValues(values, 1, values.n))
                elseif op == 33 then
                    local values = registers[b]
                    registers[a](unpackValues(values, 1, values.n))
                elseif op == 34 then
                    registers[a]=constants[b]
                    remaining=remaining-1;if remaining<0 then error('Nil instruction budget exceeded',0)end
                    registers[c]=constants[d]
                elseif op == 35 then
                    registers[a]=constants[b]
                    remaining=remaining-1;if remaining<0 then error('Nil instruction budget exceeded',0)end
                    cells[c]={v=registers[a]}
                elseif op == 36 then
                    registers[a]=constants[b]
                    remaining=remaining-1;if remaining<0 then error('Nil instruction budget exceeded',0)end
                    cells[c].v=registers[a]
                elseif op == 37 then
                    registers[a]=constants[b]
                    remaining=remaining-1;if remaining<0 then error('Nil instruction budget exceeded',0)end
                    registers[c]=registers[d][registers[a]]
                elseif op == 38 then
                    registers[a]=cells[b].v
                    remaining=remaining-1;if remaining<0 then error('Nil instruction budget exceeded',0)end
                    registers[c]=registers[a][registers[d]]
                else invalid() end
            end
        end
    end
    return make(entry, {})
end
