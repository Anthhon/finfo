local ELF = {}

ELF.MAGICNUM = "\x7F\x45\x4C\x46"

ELF.CLASS = {
    [1] = "32-bit",
    [2] = "64-bit"
}

ELF.DATA = {
    [1] = "little-endian",
    [2] = "big-endian"
}

ELF.ETYPE = {
    [0x00] = "NONE",
    [0x01] = "REL",
    [0x02] = "EXEC",
    [0x03] = "DYN",
    [0x04] = "CORE",
    [0xFE00] = "LOOS",
    [0xFEFF] = "HIOS",
    [0xFF00] = "LOPROC",
    [0xFFFF] = "HIPROC",
}

ELF.OSABI = {
    [0x00] = "UNIX | System V",
    [0x01] = "HP-UX",
    [0x02] = "NetBSD",
    [0x03] = "Linux",
    [0x04] = "GNU Hurd",
    [0x06] = "Solaris",
    [0x07] = "AIX (Monterey)",
    [0x08] = "IRIX",
    [0x09] = "FreeBSD",
    [0x0A] = "Tru64",
    [0x0B] = "Novell Modesto",
    [0x0C] = "OpenBSD",
    [0x0D] = "OpenVMS",
    [0x0E] = "NonStop Kernel",
    [0x0F] = "AROS",
    [0x10] = "FenixOS",
    [0x11] = "Nuxi CloudABI",
    [0x12] = "Stratus Technologies OpenVOS",
}

ELF.MACHINE = {
    [0x03] = "x86",
    [0x28] = "ARM",
    [0x3E] = "x86-64",
    [0xB7] = "AArch64",
    [0xF3] = "RISC-V"
}

-- Return table with ELF info, or nil + err reason
function ELF.parseHeader(data)
    if #data < 16 then
        return nil, "file too small for ELF identification"
    end

    if data:sub(1,4) ~= ELF.MAGICNUM then
        return nil, "bad magic number"
    end

    local class = data:byte(5)
    local endianness = data:byte(6)
    local ident_version = data:byte(7)
    local osabi = data:byte(8)
    local abi_version = data:byte(9)

    -- Treats data based on the file endianness
    local endian
    if endianness == 1 then
        endian = "<"
    elseif endianness == 2 then
        endian = ">"
    else
        return nil, "invalid ELF data encoding"
    end

    -- Gets header size based on bits data size
    local header_size
    if class == 1 then
        header_size = 32
    elseif class == 2 then
        header_size = 64
    else
        return nil, "invalid ELF class"
    end

    -- Check if header has at least the minimum size
    if #data < header_size then
        return nil, "file too small for ELF header"
    end

    -- Common fields
    local etype = string.unpack(endian .. "I2", data, 17)
    local machine = string.unpack(endian .. "I2", data, 19)
    local version = string.unpack(endian .. "I4", data, 21)

    -- Dynamic address fields
    local entry
    local phoff
    local shoff
    local flags
    local ehsize
    local phentsize
    local phnum
    local shentsize
    local shnum
    local shstrndx

    if class == 1 then
        -- ELF32
        entry = string.unpack(endian .. "I4", data, 25)
        phoff = string.unpack(endian .. "I4", data, 29)
        shoff = string.unpack(endian .. "I4", data, 33)
        flags = string.unpack(endian .. "I4", data, 37)

        ehsize = string.unpack(endian .. "I2", data, 41)
        phentsize = string.unpack(endian .. "I2", data, 43)
        phnum = string.unpack(endian .. "I2", data, 45)
        shentsize = string.unpack(endian .. "I2", data, 47)
        shnum = string.unpack(endian .. "I2", data, 49)
        shstrndx = string.unpack(endian .. "I2", data, 51) 
    elseif class == 2 then
        -- ELF64
        entry = string.unpack(endian .. "I8", data, 25)
        phoff = string.unpack(endian .. "I8", data, 33)
        shoff = string.unpack(endian .. "I8", data, 41)
        flags = string.unpack(endian .. "I4", data, 49)

        ehsize = string.unpack(endian .. "I2", data, 53)
        phentsize = string.unpack(endian .. "I2", data, 55)
        phnum = string.unpack(endian .. "I2", data, 57)
        shentsize = string.unpack(endian .. "I2", data, 59)
        shnum = string.unpack(endian .. "I2", data, 61)
        shstrndx = string.unpack(endian .. "I2", data, 63)
    end

    return {
        class = ELF.CLASS[class] or string.format("unknown (0x%02x)", class),

        data = ELF.DATA[endianness]
            or string.format("unknown (0x%02x)", endianness),

        ident_version = ident_version == 1
            and "1 (current)"
            or string.format("0x%02x", ident_version),

        osabi = ELF.OSABI[osabi]
            or string.format("unknown (0x%02x)", osabi),

        abi_version = abi_version,

        type = ELF.ETYPE[etype]
            or string.format("0x%04x", etype),

        machine = ELF.MACHINE[machine]
            or string.format("0x%04x", machine),

        version = version == 1
            and "1 (current)"
            or string.format("0x%08x", version),

        entry = entry,
        phoff = phoff,
        shoff = shoff,
        flags = flags,
        ehsize = ehsize,
        phentsize = phentsize,
        phnum = phnum,
        shentsize = shentsize,
        shnum = shnum,
        shstrndx = shstrndx,
    }
end

return ELF
