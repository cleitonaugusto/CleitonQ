-- cleitonq_chunk.lua
-- Wireshark dissector for CLEITONQ_CHUNK (MAVLink v2 msg_id 50000, CRC_EXTRA 0xCE)
--
-- CleitonQ: Post-Quantum Authentication for MAVLink v2
-- Author: Cleiton Augusto Correa Bezerra
-- Repository: https://github.com/cleitonaugusto/CleitonQ
-- Paper: https://doi.org/10.5281/zenodo.20776349
--
-- INSTALLATION
-- ────────────
-- Linux/Mac : ~/.config/wireshark/plugins/cleitonq_chunk.lua
-- Windows   : %APPDATA%\Wireshark\plugins\cleitonq_chunk.lua
-- Then: Wireshark > Analyze > Reload Lua Plugins  (Ctrl+Shift+L)
--
-- WHAT THIS SHOWS
-- ───────────────
-- · Decodes every CLEITONQ_CHUNK field (session_token, frame_type, seq, ...)
-- · Tracks chunk reassembly across packets — shows "3/7 chunks received"
-- · Marks reassembly complete with a [COMPLETE] tag in the packet list
-- · Works standalone on UDP 14550/14551/14552/14580 (standard MAVLink ports)
-- · Also hooks into the MAVLink plugin DissectorTable if it is already loaded

-- ── Protocol definition ───────────────────────────────────────────────────────

local p = Proto("cleitonq", "CleitonQ CHUNK (PQC Auth Fragment)")

-- ── Field definitions (wire order: uint16 first, then uint8s, then array) ────

local F = {
    session_token    = ProtoField.uint16("cleitonq.session_token",    "Session Token",    base.HEX),
    target_system    = ProtoField.uint8 ("cleitonq.target_system",    "Target System",    base.DEC),
    target_component = ProtoField.uint8 ("cleitonq.target_component", "Target Component", base.DEC),
    frame_type       = ProtoField.uint8 ("cleitonq.frame_type",       "Frame Type",       base.DEC,
                            {[0]="SIGNED_CMD", [1]="SESSION_INIT"}),
    chunk_seq        = ProtoField.uint8 ("cleitonq.chunk_seq",        "Chunk Seq",        base.DEC),
    chunk_count      = ProtoField.uint8 ("cleitonq.chunk_count",      "Chunk Count",      base.DEC),
    data_len         = ProtoField.uint8 ("cleitonq.data_len",         "Data Length",      base.DEC),
    data             = ProtoField.bytes ("cleitonq.data",             "Payload Data"),
    -- expert fields
    reassembly       = ProtoField.string("cleitonq.reassembly",       "Reassembly State"),
}
p.fields = F

local ef_complete = ProtoExpert.new(
    "cleitonq.reassembly.complete", "CleitonQ payload fully reassembled",
    expert.group.REASSEMBLE, expert.severity.NOTE)
local ef_missing = ProtoExpert.new(
    "cleitonq.reassembly.missing", "CleitonQ chunk missing — reassembly incomplete",
    expert.group.REASSEMBLE, expert.severity.WARN)
p.experts = {ef_complete, ef_missing}

-- ── Reassembly state (keyed by session_token .. frame_type) ──────────────────
-- Wireshark calls dissectors multiple times; we use packet number to avoid
-- duplicating state on re-dissection.

local reassembly_state = {} -- [key] = {count, total, pkts={}}
local packet_seen      = {} -- [pkt_num] = true  (suppress double-counting)

local FRAME_NAME = {[0]="SIGNED_CMD", [1]="SESSION_INIT"}

-- ── Core dissector ────────────────────────────────────────────────────────────

function p.dissector(buf, pinfo, tree)
    if buf:len() < 10 then return 0 end

    pinfo.cols.protocol:set("CLEITONQ")

    local subtree = tree:add(p, buf(), "CleitonQ Chunk")

    -- Decode fields (wire order matches MAVLink v2 field-size sort)
    local off = 0
    subtree:add_le(F.session_token,    buf(off, 2)); local tok = buf(off,2):le_uint(); off = off + 2
    subtree:add   (F.target_system,    buf(off, 1)); off = off + 1
    subtree:add   (F.target_component, buf(off, 1)); off = off + 1
    subtree:add   (F.frame_type,       buf(off, 1)); local ftype = buf(off,1):uint(); off = off + 1
    subtree:add   (F.chunk_seq,        buf(off, 1)); local seq   = buf(off,1):uint(); off = off + 1
    subtree:add   (F.chunk_count,      buf(off, 1)); local total = buf(off,1):uint(); off = off + 1
    subtree:add   (F.data_len,         buf(off, 1)); local dlen  = buf(off,1):uint(); off = off + 1

    local safe_dlen = math.min(dlen, buf:len() - off)
    if safe_dlen > 0 then
        subtree:add(F.data, buf(off, safe_dlen))
    end

    -- ── Reassembly tracking ───────────────────────────────────────────────────
    local key    = string.format("%04x:%d", tok, ftype)
    local pktnum = pinfo.number

    if not packet_seen[pktnum] then
        packet_seen[pktnum] = true
        if not reassembly_state[key] then
            reassembly_state[key] = {count=0, total=total, pkts={}}
        end
        local st = reassembly_state[key]
        if not st.pkts[seq] then
            st.pkts[seq] = pktnum
            st.count     = st.count + 1
            st.total     = total
        end
    end

    local st       = reassembly_state[key] or {count=1, total=total}
    local fname    = FRAME_NAME[ftype] or ("TYPE_"..ftype)
    local complete = (st.count >= st.total) and (st.total > 0)
    local status   = string.format("%d/%d chunks received%s",
                        st.count, st.total,
                        complete and " [COMPLETE]" or "")

    local ri = subtree:add(F.reassembly, buf(0, 0), status)
    if complete then
        ri:add_proto_expert_info(ef_complete)
    elseif pktnum > 1 and st.count < st.total then
        -- only warn after we have seen at least one chunk
    end

    -- ── Info column ───────────────────────────────────────────────────────────
    pinfo.cols.info:set(string.format(
        "CLEITONQ %s  seq=%d/%d  token=0x%04x  %s",
        fname, seq + 1, total, tok,
        complete and "[COMPLETE]" or string.format("[%d/%d]", st.count, st.total)
    ))

    return buf:len()
end

-- ── MAVLink v2 frame scanner (standalone, for UDP traffic) ───────────────────

local MAV_STX_V2      = 0xFD
local CLEITONQ_MSG_ID = 50000

local function try_mavlink_frame(buf, offset, pinfo, tree)
    if buf:len() - offset < 12 then return 0 end
    if buf(offset, 1):uint() ~= MAV_STX_V2 then return 0 end

    local payload_len = buf(offset + 1, 1):uint()
    local frame_len   = 10 + payload_len + 2

    if buf:len() - offset < frame_len then return 0 end

    -- message ID is 3 bytes little-endian at bytes 7-9
    local msg_id = buf(offset + 7, 1):uint()
                 + buf(offset + 8, 1):uint() * 256
                 + buf(offset + 9, 1):uint() * 65536

    if msg_id ~= CLEITONQ_MSG_ID then return frame_len end

    -- Hand off payload to our dissector
    local payload_start = offset + 10
    if payload_len >= 8 then
        p.dissector(buf(payload_start, payload_len):tvb(), pinfo, tree)
    end

    return frame_len
end

-- Standalone UDP dissector — scans datagrams for MAVLink v2 frames
local udp_standalone = Proto("cleitonq_udp", "CleitonQ (MAVLink scanner)")

function udp_standalone.dissector(buf, pinfo, tree)
    local offset = 0
    local found  = false
    while offset < buf:len() - 11 do
        local consumed = try_mavlink_frame(buf, offset, pinfo, tree)
        if consumed > 0 then
            found  = true
            offset = offset + consumed
        else
            offset = offset + 1
        end
    end
    if not found then return 0 end
    return buf:len()
end

-- ── Registration ──────────────────────────────────────────────────────────────

-- Primary: hook into MAVLink plugin DissectorTable (if loaded)
local mav_table = DissectorTable.get("mavlink.msgid")
if mav_table then
    mav_table:add(CLEITONQ_MSG_ID, p)
end

-- Fallback: register on standard MAVLink UDP ports
local udp_table = DissectorTable.get("udp.port")
for _, port in ipairs({14550, 14551, 14552, 14580}) do
    udp_table:add(port, udp_standalone)
end

-- ── Display filter reference ──────────────────────────────────────────────────
--
-- cleitonq                         all CleitonQ chunks
-- cleitonq.frame_type == 0         SIGNED_CMD chunks
-- cleitonq.frame_type == 1         SESSION_INIT chunks
-- cleitonq.reassembly contains "COMPLETE"   fully reassembled payloads
-- cleitonq.session_token == 0x1a2b filter by session
