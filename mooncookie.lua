local libmoon	= require "libmoon"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log		= require "log"
local ffi		= require "ffi"
local proto		= require "proto/proto"
local check		= require "proto/packetChecks"

-- tcp SYN defense strategies
local cookie	= require "src/synCookie"
local auth		= require "src/synAuthentication"

-- Adjust luajit parameters
local jit = require "jit"
jit.opt.start("maxrecord=10000", "maxirconst=1000", "loopunroll=40")

-- implemented strategies
local STRAT = {
	cookie 		= 1,
	auth_invalid= 2,
	auth_full	= 3,
	auth_ttl	= 4,
}

function configure(parser)
	parser:description("MoonCookie - a TCP SYN Proxy")
	parser:argument("dev", "Device to use"):args(1):convert(tonumber)
	strats = ""
	first = true
	for k,_ in pairs(STRAT) do
		if first then
			strats = k
			first = false
		else
			strats = strats .. "|" .. k
		end
	end
	parser:option("-s --strategy", "Mitigation strategy [" .. strats .. "]"):args("1"):convert(STRAT):default('cookie')
	parser:option("-t --threads", "Number of threads to start"):args(1):convert(tonumber):default(1)
	return parser:parse()
end

function master(args, ...)
	local dev = device.config{ 
		port = args.dev ,
		txQueues = args.threads,
		rxQueues = args.threads,
		rssQueues = args.threads
	}
	device.waitForLinks()

	for i = 1, args.threads do
		libmoon.startTask("synProxyTask", dev, args.strategy, i - 1)
	end
	stats.startStatsTask{dev} 
	libmoon.waitForTasks()
end


----------------------------------------------------
-- check packet type
----------------------------------------------------

local isIP4 	= check.isIP4
local isTcp4 	= check.isTcp4


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

local verifyCookie 				= cookie.verifyCookie
local sequenceNumberTranslation = cookie.sequenceNumberTranslation
local createSynAckToClient 		= cookie.createSynAckToClient
local createSynToServer 		= cookie.createSynToServer
local createAckToServer 		= cookie.createAckToServer
local forwardTraffic 			= cookie.forwardTraffic
local forwardStalled 			= cookie.forwardStalled
local calculateCookiesBatched 	= cookie.calculateCookiesBatched


-------------------------------------------------------------------------------------------
---- Syn Auth
-------------------------------------------------------------------------------------------

local forwardTrafficAuth 		= auth.forwardTraffic
local createResponseAuthInvalid	= auth.createResponseAuthInvalid
local createResponseAuthFull 	= auth.createResponseAuthFull
local createResponseRst 		= auth.createResponseRst


---------------------------------------------------
-- task
---------------------------------------------------

local function info(msg, id)
	print(getColorCode(id + 1) .. '[MoonCookie: id=' .. id .. '] ' .. getColorCode("white") .. msg)
end

function synProxyTask(dev, strategy, threadId)
	info('Initialising SYN proxy', threadId)

	local maxBurstSize = 63

	-- RX buffers for left
	local lRXQueue = dev:getRxQueue(threadId)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray(maxBurstSize)

	-- TX buffers
	local lTXQueue = dev:getTxQueue(threadId)

	-- buffer for cookie syn/ack to left
	local numSynAck = 0
	local lTXSynAckBufs = cookie.getSynAckBufs()
	
	-- ack to right (on syn/ack from right)
	local numAck = 0
	local rTXAckBufs = cookie.getAckBufs()
	
	-- buffer for forwarding
	local numForward = 0 
	local lTXForwardBufs = cookie.getForwardBufs()
	
	-- buffer for syn auth answer to left
	local numAuth = 0
	local lTXAuthBufs = auth.getSynAckBufs()
	
	-- buffer for rst answer to left
	local numRst = 0
	local lTXRstBufs = auth.getRstBufs()

	-- buffers for not TCP packets
	-- need to behandled separately as we cant just offload TCP checksums here
	-- its only a few packets anyway, so handle them separately
	local txNotTcpMem = memory.createMemPool()	
	local txNotTcpBufs = txNotTcpMem:bufArray(1)


	-------------------------------------------------------------
	-- State keeping data structure
	-------------------------------------------------------------
	local stateCookie
	local bitMapAuth
	local bitMapAuthTtl
	if strategy == STRAT['cookie'] then
		stateCookie = cookie.createSparseHashMapCookie()
	elseif strategy == STRAT['auth_ttl'] then
		bitMapAuthTtl = auth.createBitMapAuthTtl()
	else
		bitMapAuth = auth.createBitMapAuth()
	end
	

	-------------------------------------------------------------
	-- mempool and buffer to store stalled segments
	-------------------------------------------------------------
	local stallMem = memory.createMemPool()
	local stallBufs = stallMem:bufArray(1)


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	info('Starting SYN proxy', threadId)
	while libmoon.running() do
		rx = lRXQueue:tryRecv(lRXBufs, 1)
		numSynAck = 0
		numAck = 0
		numForward = 0
		numAuth = 0
		for i = 1, rx do
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			--lRXBufs[i]:dump()
			if not isTcp4(lRXPkt) then
				--log:debug('Sending packet that is not TCP')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], lRXBufs[i])
				lTXQueue:sendN(txNotTcpBufs, 1)
			else -- TCP
				--lRXBufs[i]:dump()
				-- TCP SYN Authentication strategy
				if strategy == STRAT['auth_invalid'] then
					-- send wrong acknowledgement number on unverified SYN
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuth:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuthInvalid(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						if bitMapAuth:isWhitelisted(lRXPkt) then
							forward = true
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTrafficAuth(lTXForwardBufs[numForward], lRXBufs[i])
					end
				elseif strategy == STRAT['auth_full'] then
					-- do a full handshake for whitelisting, then proxy sends rst
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuth:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuthFull(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						local action = bitMapAuth:isWhitelistedFull(lRXPkt) 
						if action == 1 then
							forward = true
						elseif action == 2 then
							-- send rst
							if numRst == 0 then
								lTXRstBufs:allocN(60, rx - (i - 1))
							end
							numRst = numRst + 1
							createResponseRst(lTXRstBufs[numRst], lRXPkt)
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTrafficAuth(lTXForwardBufs[numForward], lRXBufs[i])
					end
				elseif strategy == STRAT['auth_ttl'] then
					-- send wrong acknowledgement number on unverified SYN
					-- only accept the RST from the client if the TTL values match
					local forward = false
					if lRXPkt.tcp:getSyn() and not lRXPkt.tcp:getAck() then
						if bitMapAuthTtl:isWhitelistedSyn(lRXPkt) then
							forward = true
						else
							-- create and send packet with wrong sequence number
							if numAuth == 0 then
								lTXAuthBufs:allocN(60, rx - (i - 1))
							end
							numAuth = numAuth + 1
							createResponseAuth(lTXAuthBufs[numAuth], lRXPkt)
						end
					else
						if bitMapAuthTtl:isWhitelisted(lRXPkt) then
							forward = true
						else
							-- drop
							-- we either received a rst that now whitelisted the connection
							-- or we received not whitelisted junk
						end
					end
					if forward then
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTrafficAuth(lTXForwardBufs[numForward], lRXBufs[i])
					end
				else
				-- TCP SYN Cookie strategy
					if lRXPkt.tcp:getSyn() then
						if not lRXPkt.tcp:getAck() then -- SYN -> send SYN/ACK
							--log:debug('Received SYN from left')
							if numSynAck == 0 then
								lTXSynAckBufs:allocN(60, rx - (i - 1))
							end
							numSynAck = numSynAck + 1
							createSynAckToClient(lTXSynAckBufs[numSynAck], lRXPkt)
						else -- SYN/ACK from right -> send ack + stall table lookup
							--log:debug('Received SYN/ACK from server, sending ACK back')
							local diff, stalled = stateCookie:setRightVerified(lRXPkt)
							if diff then
								-- ack to server
								rTXAckBufs:allocN(60, 1)
								createAckToServer(rTXAckBufs[1], lRXBufs[i], lRXPkt)
								rTXAckBufs[1]:offloadTcpChecksum()
								lTXQueue:sendSingle(rTXAckBufs[1])
									
								if stalled then
									forwardStalled(diff, stalled)
									stalled:offloadTcpChecksum()
									lTXQueue:sendSingle(stalled)
								end
							else
								log:debug("right verify failed")
							end
						end
					-- any verified packet from server
					else -- check verified status
						local diff, stalled = stateCookie:isVerified(lRXPkt) 
						if not diff and lRXPkt.tcp:getAck() then -- finish handshake with left, start with right
							--log:debug("verifying cookie")
							local mss, wsopt = verifyCookie(lRXPkt)
							if mss then
								--log:debug('Received valid cookie from left, starting handshake with server')
								
								stateCookie:setLeftVerified(lRXPkt)
								-- connection is left verified, start handshake with right
								if numForward == 0 then
									lTXForwardBufs:allocN(60, rx - (i - 1))
								end
								numForward = numForward + 1
								createSynToServer(lTXForwardBufs[numForward], lRXBufs[i], mss, wsopt)
							else
								--log:warn('Wrong cookie, dropping packet ')
								-- drop, and done
								-- most likely simply the timestamp timed out
								-- but it might also be a DoS attack that tried to guess the cookie
							end
						elseif not diff then
							-- not verified, not ack -> drop
							--log:warn("dropping unverfied not ack packet")
						elseif diff == "stall" then
							stallBufs:allocN(60, 1)
							ffi.copy(stallBufs[1]:getData(), lRXBufs[i]:getData(), lRXBufs[i]:getSize())
							stallBufs[1]:setSize(lRXBufs[i]:getSize())
							stalled.stalled = stallBufs[1]
						elseif diff then 
							--log:debug('Received packet of verified connection, translating and forwarding')
							if numForward == 0 then
								lTXForwardBufs:allocN(60, rx - (i - 1))
							end
							numForward = numForward + 1
							sequenceNumberTranslation(diff, lRXBufs[i], lTXForwardBufs[numForward], lRXPkt, lTXForwardBufs[numForward]:getTcp4Packet())
						else
							-- should not happen
							log:error('unhandled packet ' )
						end
					end
				end
			end
		end
		if rx > 0 then
			-- strategy specific responses
			if strategy == STRAT['cookie'] then	
				if numSynAck > 0 then
					-- send syn ack
					calculateCookiesBatched(lTXSynAckBufs.array, numSynAck)
					lTXSynAckBufs:offloadTcpChecksums(nil, nil, nil, numSynAck)
					lTXQueue:sendN(lTXSynAckBufs, numSynAck)
					lTXSynAckBufs:freeAfter(numSynAck)
				end
			else
				-- send packets with wrong ack number
				if numAuth > 0 then
					lTXAuthBufs:offloadTcpChecksums(nil, nil, nil, numAuth)
					lTXQueue:sendN(lTXAuthBufs, numAuth)
					lTXAuthBufs:freeAfter(numAuth)
				end
			end
			-- all strategies
			-- send forwarded packets and free unused buffers
			if numForward > 0 then
				-- authentication strategies dont touch anything above ethernet
				-- offloading would set checksums to 0 -> dont
				if strategy == STRAT['cookie'] then
					lTXForwardBufs:offloadTcpChecksums(nil, nil, nil, numForward)
				end
				lTXQueue:sendN(lTXForwardBufs, numForward)
				lTXForwardBufs:freeAfter(numForward)
			end
			
			-- no rx packets reused --> free
			lRXBufs:freeAll(rx)
		end
	end
	info('Finished SYN proxy', threadId)
end
