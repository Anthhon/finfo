local HELPER = {}

function HELPER.fileRead(path)
    local f, err = io.open(path, "rb")
    if not f then
        return nil, err
    end

    local content, rerr = f:read("a")
    f:close()
    if not content then
        return nil, rerr
    end
    return content
end

function HELPER.hexDump(data)
    local chunkSize = 16
    for offset = 0, #data - 1, chunkSize do
        -- Outputs chunk addr + hex bytes + ascii
        local chunk = data:sub(offset + 1, offset + chunkSize)
        local hex = (chunk:gsub(".", function(c) return ("%02x "):format(c:byte()) end))
        local ascii = (chunk:gsub("[^\32-\126]", "."))

        io.write(("%08x  %-48s |%s|\n"):format(offset, hex, ascii))
    end
end

return HELPER
