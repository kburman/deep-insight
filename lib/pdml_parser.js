var util = require('util')
var transform = require('stream').Transform
var cio = require('cheerio')


/*
	Input : stream of pdml in xml format
	Output: packet object

	It can parse pdml stream from tshark
	and even filter to drop noise or unwanted 
	packet 
*/

var PACKET_START = "<packet>"
var PACKET_END   = "</packet>"
var PACKET_START_LEN = PACKET_START.length
var PACKET_END_LEN = PACKET_END.length

/*
	IP:PROTO
	17 = UDP

	BOOPT:TYPE
	1 = Request
	2 = Response

	DNS:QRY.type
	0x01 = HOST(A) record
	0x02 = Name Server record
	0x05 = Alias(CNAME) record
	0x0C = Reverse lookup (PTR)
	0x0F = Mail Exchange (MX)
	0x21 = Service (SRV) record
	0xFF = All records

	DNS:QRY.class
	0x01 = Class IN (for internet)

	
*/

function pdmlParser (option) {
	if (!(this instanceof pdmlParser)) {
		return new pdmlParser(option)
	}
	this._packetBuffer = ""
	this._count = 0
	transform.call(this, option)
}

util.inherits(pdmlParser, transform)

pdmlParser.prototype._transform = function(chunk, encoding, done) {
	this._packetBuffer += chunk.toString()
	this._parseBuffer()
	done()
}

pdmlParser.prototype._parseBuffer = function() {
	while(this._parsePacket());
}

pdmlParser.prototype._parsePacket = function() {
	var si = this._packetBuffer.indexOf(PACKET_START)
	var ei = this._packetBuffer.indexOf(PACKET_END)	
	if (si == -1 || ei == -1) {
		return false
	}

	if (ei < si) {
		throw new Error('ei < si')
	}

	var packetData = this._packetBuffer.substring(si, ei + PACKET_END_LEN)
	this._packetBuffer = this._packetBuffer.substring(ei + PACKET_END_LEN)
	var packet = this._processPacket(packetData)
	this.emit('packet', packet)
	return true
}

pdmlParser.prototype._processPacket = function(packetData) {
	$ = cio.load(packetData, {
		xmlMode: true
	})
	var packet = {}
	packet.isMalformed = false
	$('proto').each(function (i, elem) {
		switch($(this).attr('name'))
		{
			case 'frame':
				packet.protos = $('field[name="frame.protocols"]', this).attr('show')
				packet.timestamp = $('field[name="frame.time"]', this).attr('show')
				break
			case 'eth':
				packet.eth_dst = $('field[name="eth.dst"]', this).attr('value')
				packet.eth_src = $('field[name="eth.src"]', this).attr('value')
				break

			case 'wlan':
				packet.reciver_address_mac = $('field[name="wlan.ra"]', this).attr('value')
				packet.sender_address_mac = $('field[name="wlan.sa"]', this).attr('value')
				packet.transmitter_address_mac = $('field[name="wlan.ta"]', this).attr('value')
				packet.bssid = $('field[name="wlan.bssid"]', this).attr('value')
				break
			case 'ip':
				packet.ip_proto = $('field[name="ip.proto"]').attr('show')	//base10 format
				packet.src_ip = $('field[name="ip.src"]').attr('show')
				packet.dst_ip = $('field[name="ip.dst"]').attr('show')
				break
			case 'udp':
				packet.udp_srcport = $('field[name="udp.srcport"]').attr('show')
				packet.udp_dstport = $('field[name="udp.dstport"]').attr('show')				
				break
			case 'bootp':
				packet.bootp_type = $('field[name="bootp.type"]').attr('show')
				packet.bootp_hostname = $('field[name="bootp.option.hostname"]').attr('show')
				packet.bootp_vendorclassid = $('field[name="bootp.option.vendor_class_id"]').attr('show')
				break
			case 'tcp':
				packet.tcp_srcport = $('field[name="tcp.srcport"]').attr('show')
				packet.tcp_dstport = $('field[name="tcp.dstport"]').attr('show')
				packet.tcp_ack = $('field[name="tcp.ack"]').attr('show')
				packet.tcp_seq = $('field[name="tcp.seq"]').attr('show')
				packet.tcp_segdata = $('field[name="tcp.segment_data"]').attr('show')
				break			
			case 'dns':
				packet.dns_queryc = $('field[name="dns.queries"]').attr('show')
				packet.dns_ansc = $('field[name="dns.answers"]').attr('show')
				dns_queries = []
				$('field[show="Queries"] > field').each(function (i, elem) {
					var tmp = {}
					tmp.qname = $('field[name="dns.qry.name"]', this).attr('show')
					tmp.qtype = $('field[name="dns.qry.type"]', this).attr('show')
					tmp.qclass = $('field[name="dns.qry.class"]', this).attr('show')
					dns_queries.push(tmp)
				})
				packet.dns_queries = dns_queries
				break
			case 'http':
				packet.http_method = $('field[name="http.request.method"]', this).attr('show')
				packet.http_path = $('field[name="http.request.uri"]', this).attr('show')
				packet.http_fulluri = $('field[name="http.request.full_uri"]', this).attr('show')
				packet.http_ua = $('field[name="http.user_agent"]', this).attr('show')
				packet.http_host = $('field[name="http.host"]', this).attr('show')
				packet.http_cookie = $('field[name="http.cookie"]', this).attr('show')
				packet.http_authbasic = $('field[name="http.authbasic"]', this).attr('show')
				packet.http_location = $('field[name="http.location"]', this).attr('show')
				packet.http_referer = $('field[name="http.referer"]', this).attr('show')
				packet.http_respcode = $('field[name="http.response.code"]', this).attr('show')
				packet.http_server = $('field[name="http.server"]', this).attr('show')
				packet.http_wauth = $('field[name="http.www_authenticate"]', this).attr('show')

				break

			case 'browser':
				packet.browser_cname = $('field[name="browser.response_computer_name"]', this).attr('show')
				break

			case 'nbns':
				packet.nbns_queryc = $('field[name="nbns.count.queries"]').attr('show')
				packet.nbns_ansc = $('field[name="nbns.count.answers"]').attr('show')
				dns_queries = []
				$('field[show="Queries"] > field').each(function (i, elem) {
					var tmp = {}
					tmp.qname = $('field[name="dns.qry.name"]', this).attr('show')
					tmp.qtype = $('field[name="dns.qry.type"]', this).attr('show')
					tmp.qclass = $('field[name="dns.qry.class"]', this).attr('show')
					dns_queries.push(this)
				})
				//packet.nbns_queries = dns_queries
				break


			case 'malformed':
				packet.isMalformed = true
				break

			// not intersting
			case 'llc':
			case 'geninfo':
			case 'ntp':
			case 'ssl':
			case 'ipv6':
			case 'dhcpv6':
				break

			default:
				break

		}
	})

	return packet
}



module.exports = pdmlParser