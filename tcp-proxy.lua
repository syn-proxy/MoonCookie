local mg		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log		= require "log"
local kni 		= require "kni"
local ffi		= require "ffi"
local dpdkc 	= require "dpdkc"
local proto		= require "proto/proto"
local check		= require "proto/packetChecks"

local hashMap 	= require "hashMap" -- TODO move to synCookie.lua
local bitMap 	= require "bitMap"

-- tcp SYN defense strategies
local cookie	= require "src/synCookie"
local auth		= require "src/synAuthentication"

-- utility
local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift

-- Adjust luajit parameters
local jit = require "jit"
jit.opt.start("maxrecord=10000", "maxirconst=1000", "loopunroll=40")

---------------------------------------------------
-- Usage
---------------------------------------------------
-- TODO config for interfaces etc

function master(rxPort, txPort)
	if not txPort or not rxPort then
		log:info("Usage: rxPort txPort")
		return
	end
	txPort = tonumber(txPort)
	rxPort = tonumber(rxPort)
	
	log:info('Initialize KNI')
	kni.init(4)
	
	local lRXDev = device.config{ port = rxPort, txQueues=2 }
	local lTXDev = device.config{ port = txPort }
	lRXDev:wait()
	lTXDev:wait()
	mg.launchLua("tcpProxySlave", lRXDev, lTXDev)
	
	mg.waitForSlaves()
	
	log:info('Closing KNI')
	kni.close()
end


---------------------------------------------------
-- Constants
---------------------------------------------------

local LEFT_TO_RIGHT = cookie.LEFT_TO_RIGHT
local RIGHT_TO_LEFT = cookie.RIGHT_TO_LEFT

local STRAT = {
	cookie 	= 1,
	auth	= 2,
}


----------------------------------------------------
-- check packet type
----------------------------------------------------

local isIP4 = check.isIP4
local isTcp4 = check.isTcp4


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

local verifyCookie = cookie.verifyCookie
local sequenceNumberTranslation = cookie.sequenceNumberTranslation
local createSynAckToClient = cookie.createSynAckToClient
local createSynToServer = cookie.createSynToServer
local createAckToServer = cookie.createAckToServer


-------------------------------------------------------------------------------------------
---- Syn Auth
-------------------------------------------------------------------------------------------

local forwardTraffic = auth.forwardTraffic
local createResponseAuth = auth.createResponseAuth


---------------------------------------------------
-- slave
---------------------------------------------------

function tcpProxySlave(lRXDev, lTXDev)
	log:setLevel("ERROR")
	
	local currentStrat = STRAT['auth']
	local maxBurstSize = 63

	-------------------------------------------------------------
	-- right/virtual interface
	-------------------------------------------------------------
	-- Create KNI device
	log:info('Creating virtual device')
	local virtualDevMemPool = memory.createMemPool{ n=8192 }
	local virtualDev = kni.createKni(0, lRXDev, virtualDevMemPool, "vEth0")
	log:info('Ifconfig virtual device')
	virtualDev:setIP("192.168.1.1", 24)

	log:info('ARP entry for client') -- TODO use ARP task
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")

	-- not sure but without this it doesn't work
	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end

	log:info('Set default route')
	io.popen("ip r add default via 192.168.1.201")
	log:info('Set ARP for HTTP')
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")
	log:info('Set ARP for DoS')
	io.popen("/usr/sbin/arp -s 192.168.1.201 90:e2:ba:98:58:79")
	
	-- RX buffers for right
	local rRXMem = memory.createMemPool()	
	local rRXBufs = virtualDevMemPool:bufArray()
	
	-- TX buffers 
	-- ack to right (on syn/ack from right)
	local numAck = 0
	local rTXAckMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local rTXAckBufs = virtualDevMemPool:bufArray(1)
	
	-- right to left forward
	local lTXForwardQueue = lTXDev:getTxQueue(1)
	
	local numForward = 0
	local rTXForwardMem = memory.createMemPool()
	local rTXForwardBufs = virtualDevMemPool:bufArray()


	-------------------------------------------------------------
	-- left/physical interface
	-------------------------------------------------------------
	lTXStats = stats:newDevTxCounter(lTXDev, "plain")
	lRXStats = stats:newDevRxCounter(lRXDev, "plain")
	
	-- RX buffers for left
	local lRXQueue = lRXDev:getRxQueue(0)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray()

	-- TX buffers
	local lTXQueue = lTXDev:getTxQueue(0)

	-- buffer for cookie syn/ack to left
	local numSynAck = 0
	local lTXSynAckBufs = cookie.getSynAckBufs()
	
	-- buffer for cookie forwarding to right
	-- both for syn as well as all translated traffic
	local numForward = 0 
	local lTXForwardBufs = cookie.getForwardBufs()
	
	-- buffer for syn auth answer to left
	local numAuth = 0
	local lTXAuthBufs = auth.getBufs()

	-- buffers for not TCP packets
	-- need to behandled separately as we cant just offload TCP checksums here
	-- its only a few packets anyway, so handle them separately
	local txNotTcpMem = memory.createMemPool()	
	local txNotTcpBufs = virtualDevMemPool:bufArray(1)


	-------------------------------------------------------------
	-- Hash table
	-------------------------------------------------------------
	log:info("Creating hash table")
	local hashMapCookie = hashMap.createSparseHashMapCookie()
	local bitMapAuth = bitMap.createBitMapAuth()

	
	-------------------------------------------------------------
	-- stall table
	-------------------------------------------------------------
	local stallMem = memory.createMemPool()
	local stallBufs = stallMem:bufArray(1)
	local stallTable = {}


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	log:info('Starting TCP Proxy')
	while mg.running() do
		------------------------------------------------------------------------------ poll right interface
		--log:debug('Polling right (virtual) Dev')
		-- for a real interface use tryRecv
		rx = virtualDev:recv(rRXBufs, 63)
		--log:debug(''..rx)
		if currentStrat == STRAT['cookie'] and rx > 0 then
			-- buffer for translated packets
			-- auth strategies forward all rx packets without touching them
			if currentStrat == STRAT['auth'] then
				rTXForwardBufs:allocN(60, rx)
			end
			numForward = 0
			
			numAck = 0
		end
		for i = 1, rx do
			local rRXPkt = rRXBufs[i]:getTcp4Packet()
			if not isTcp4(rRXPkt) then
				--log:info('Sending packet that is not TCP from right')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], rRXBufs[i])
				lTXQueue:sendN(txNotTcpBufs, 1)
			else
				if rRXPkt.tcp:getRst() then
					log:debug("reset right")
				end
				---------------------------------------------------------------------- process TCP
				-- handle protocol infiringement strategies
				if currentStrat == STRAT['auth'] then
					-- in all cases, we simply forward whatever we get from right
					--log:debug('doing nothing')
				-- strategie cookie
				else
					---------------------------------------------------------------------- SYN/ACK from server, finally establish connection
					if rRXPkt.tcp:getSyn() and rRXPkt.tcp:getAck() then
						--log:debug('Received SYN/ACK from server, sending ACK back')
						diff = hashMapCookie:setRightVerified(rRXPkt)
						if diff then
							-- ack to server
							rTXAckBufs:allocN(60, 1)
							createAckToServer(rTXAckBufs[1], rRXBufs[i], rRXPkt)
							virtualDev:sendSingle(rTXAckBufs[1])
								
							local index = rRXPkt.tcp:getDstString() .. rRXPkt.tcp:getSrcString() .. rRXPkt.ip4:getDstString() .. rRXPkt.ip4:getSrcString()
							local entry = stallTable[index] 

							if false then --entry then
								local pkt = entry[1]:getTcp4Packet()
								pkt.tcp:setAckNumber(pkt.tcp:getAckNumber() + diff)
								pkt.tcp:calculateChecksum(entry[1]:getData(), entry[1]:getSize(), true)
								--virtualDev:sendSingle(entry[1])
								log:debug("accessed " .. tostring(entry[2]))
								stallTable[index] = nil	
							else
								log:debug("no entry")
							end
						else
							log:debug("right verify failed")
						end
					----------------------------------------------------------------------- any verified packet from server
					else
						local diff = hashMapCookie:isVerified(rRXPkt, RIGHT_TO_LEFT) 
						if diff then
							if diff == "stall" then
								log:debug("right stall??")
							else
								-- anything else must be from a verified connection, translate and send via physical nic
								--log:info('Packet of verified connection from server, translate and forward')
								if numForward == 0 then
									rTXForwardBufs:allocN(60, rx)
								end
									
								numForward = numForward + 1
								local rTXForwardBuf = rTXForwardBufs[numForward]
								local rTXPkt = rTXForwardBuf:getTcp4Packet()

								sequenceNumberTranslation(diff, rRXBufs[i], rTXForwardBuf, rRXPkt, rTXPkt, RIGHT_TO_LEFT)
							end
						------------------------------------------------------------------------ not verified connection from server
						else
							--log:debug('Packet of not verified connection from right')
						end
					end
				end
			end
		end
		
		if currentStrat == STRAT['cookie'] then
			if rx > 0 then	
				-- forwarded to left
				if numForward > 0 then
					-- offload checksums to NIC
					--log:debug('Offloading ' .. rx)
					--rTXForwardBufs:offloadTcpChecksums(nil, nil, nil, rx)
					--log:debug('rx ' .. rx .. ' numTX2 ' .. numTX2)

					lTXForwardQueue:sendN(rTXForwardBufs, numForward)
					rTXForwardBufs:freeAfter(numForward)
				end
--log:info("Table ##################################")
--for k, v in pairs(stallTable) do
--	log:info(tostring(k) .. "->" .. tostring(v))
--end
			end
			--log:debug('free rRX')
			rRXBufs:freeAll()
		-- syn auth: simply send every received packet
		elseif rx > 0 then
			-- send all buffers, untouched
			lTXQueue:sendN(rRXBufs, rx)
		end

		------------------------------------------------------------------- polling from right interface done

		------------------------------------------------------------------- polling from left interface
		rx = lRXQueue:tryRecv(lRXBufs, 1)
		--log:debug('rx ' .. rx)
		if rx > 0 then
			if currentStrat == STRAT['cookie'] then
				numSynAck = 0
			else
				lTXAuthBufs:allocN(60, rx)
				numAuth = 0
			end

			-- every strategy needs buffers to simply forward packets left to right
			numForward = 0
		end
		for i = 1, rx do
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			if not isTcp4(lRXPkt) then
				--log:info('Sending packet that is not TCP from left')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], lRXBufs[i])
				virtualDev:sendN(txNotTcpBufs, 1)
			--------------------------------------------------------------- processing TCP
			else
				if lRXPkt.tcp:getRst() then
					log:debug("reset left")
				end
				if currentStrat == STRAT['auth'] then
					-- send wrong sequence number on unverified SYN
					if lRXPkt.tcp:getSyn() and not bitMapAuth:isWhitelisted(lRXPkt) then
						-- create and send packet with wrong sequence
						numAuth = numAuth + 1
						createResponseAuth(lTXAuthBufs[numAuth], lRXPkt)
					else
						-- react to RST and verify connection
						-- or update timestamps but only if connection was verified already
						if lRXPkt.tcp:getRst() then
							bitMapAuth:setWhitelisted(lRXPkt)
						else
							bitMapAuth:updateWhitelisted(lRXPkt)
						end
						
						-- everything else simply forward
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTraffic(lTXForwardBufs[numForward], lRXBufs[i])
					end
				else
					------------------------------------------------------------ SYN -> defense mechanism
					if lRXPkt.tcp:getSyn() then
						--log:info('Received SYN from left')
						-- strategy cookie
						if numSynAck == 0 then
							lTXSynAckBufs:allocN(60, rx - (i - 1))
							--log:debug("alloc'd with i = " .. i)
						end
						numSynAck = numSynAck + 1
						createSynAckToClient(lTXSynAckBufs[numSynAck], lRXPkt)
					-------------------------------------------------------------------------------------------------------- verified -> translate and forward
					-- check with verified connections
					-- if already verified in both directions, immediately forward, otherwise check cookie
					else
						local diff = hashMapCookie:isVerified(lRXPkt, LEFT_TO_RIGHT) 
						if diff == "stall" then
							----log:debug("stall packet")
							--local index = lRXPkt.tcp:getSrcString() .. lRXPkt.tcp:getDstString() .. lRXPkt.ip4:getSrcString() .. lRXPkt.ip4:getDstString()
							--	stallBufs:allocN(60, 1)
							--	ffi.copy(stallBufs[1]:getData(), lRXBufs[i]:getData(), lRXBufs[i]:getSize())
							--	stallBufs[1]:setSize(lRXBufs[i]:getSize())
							--	local entry =  stallTable[index] 
							--	if entry then
							--		stallTable[index] = { stallBufs[1], entry[2] + 1 }
							--	else
							--		stallTable[index] = { stallBufs[1], 1 }
							--	end
						elseif diff then 
							--log:info('Received packet of verified connection from left, translating and forwarding')
							if numForward == 0 then
								lTXForwardBufs:allocN(60, rx - (i - 1))
							end
							numForward = numForward + 1
							sequenceNumberTranslation(diff, lRXBufs[i], lTXForwardBufs[numForward], lRXPkt, lTXForwardBufs[numForward]:getTcp4Packet(), LEFT_TO_RIGHT)
						------------------------------------------------------------------------------------------------------- not verified, but is ack -> verify cookie
						elseif lRXPkt.tcp:getAck() then
							local mss, wsopt = verifyCookie(lRXPkt)
							if mss then
								--log:info('Received valid cookie from left, starting handshake with server')
								
								hashMapCookie:setLeftVerified(lRXPkt)
								-- connection is left verified, start handshake with right
								if numForward == 0 then
									lTXForwardBufs:allocN(60, rx - (i - 1))
									--log:debug("alloc'd with i = " .. i)
								end
								numForward = numForward + 1
								createSynToServer(lTXForwardBufs[numForward], lRXBufs[i], mss, wsopt)
							else
								log:warn('Wrong cookie, dropping packet ')
								-- drop, and done
								-- most likely simply the timestamp timed out
								-- but it might also be a DoS attack that tried to guess the cookie
							end
						----------------------------------------------------------------------------------------------- unverified, but not syn/ack -> ignore
						else
							-- not syn, unverified tcp packets -> belongs to already deleted connection -> drop
							log:error('unhandled packet ' )--.. tostring(isVerified(lRXPkt, LEFT_TO_RIGHT)))
						end
					end
				end
			end
		end
		if rx > 0 then
			-- strategy specific responses
			if currentStrat == STRAT['cookie'] then	
				if numSynAck > 0 then
					-- send syn ack
					lTXSynAckBufs:offloadTcpChecksums(nil, nil, nil, numSynAck)
			
					lTXQueue:sendN(lTXSynAckBufs, numSynAck)

					lTXSynAckBufs:freeAfter(numSynAck)
				end
			else
				-- send packets with wrong ack number
				lTXAuthBufs:offloadTcpChecksums(nil, nil, nil, numAuth)
				lTXQueue:sendN(lTXAuthBufs, numAuth)
			end
			-- all strategies
			-- send forwarded packets and free unused buffers
			if numForward > 0 then
				virtualDev:sendN(lTXForwardBufs, numForward)
				lTXForwardBufs:freeAfter(numForward)
			end
			
			-- no rx packets reused --> free
			lRXBufs:free(rx)
		end

		----------------------------- all actions by polling left interface done (also all buffers sent or cleared)

		lRXStats:update()
		lTXStats:update()
	end
	log:info('Releasing KNI device')
	virtualDev:release()
	
	lRXStats:finalize()
	lTXStats:finalize()

	log:info('Slave done')
end
