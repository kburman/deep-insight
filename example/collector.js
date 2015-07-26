var insight = require('../')
var tshark = insight.tshark_stream
var parser = insight.pdml_parser()
var Datastore = require('nedb')
var db = new Datastore({ filename: 'collector.db', autoload: true})


// from here our code starts
// param for starting a tshark stream
var opts = { filename: 'Open Network Connection.pcapng.cap' }
var proc = tshark(opts)

// now we will forward this stream to parser
proc.stdout.pipe(parser)

// parser will emit packet event when we read a packet
// so hookup for it
parser.on('packet', onPacket)


// heres our function to deal with packet
function onPacket (packet) {
	// first of all we need to identify from which device
	// it is comming so we will create a cid(collector id)
	// for each unique device 
	// cid will be combination of mac and ip for simplicity
	// you can design your own complex cid
	var cid = genCID(packet)
	if (cid) {
		// now we will call another function 
		// which will collection of data
		track_user(cid, packet)
	}
}


// here our job collect usefull information about cid
// from given packet and save it db
function track_user (cid, packet) {
	// every packet can't give us information 
	// or we might not need them
	if (packet.protos.indexOf('http') != -1) {
		// so this is http packet we can get
		// information about host, ua etc
		// but first we need to get doc
		// for given cid
		db.findOne({cid: cid}, function (err, doc) {
			// check if doc exits or not
			// if not then we might need to insert else we can update
			var isNew = doc == undefined
			doc = doc || {cid: cid}

			//  at first we will collect user agent
			if (packet.http_ua) {
				doc.ua = doc.ua || []
				// check if it already exits or not
				if (doc.ua.indexOf(packet.http_ua) == -1) {
					doc.ua.push(packet.http_ua)
				}
			}

			// we can also collect host name
			//  at first we will collect user agent
			if (packet.http_host) {
				doc.website = doc.website || []
				// check if it already exits or not
				if (doc.website.indexOf(packet.http_host) == -1) {
					doc.website.push(packet.http_host)
				}
			}


			// now its time to save the doc
			if (isNew) {
				db.insert(doc)
			}
			else {
				db.update({cid: cid}, doc)
			}
		})
	}
	else if (packet.protos.indexOf('browser') != -1) {
		// so this is browser packet we can get
		// information about host name
		// but first we need to get doc
		// for given cid
		db.findOne({cid: cid}, function (err, doc) {
			// check if doc exits or not
			// if not then we might need to insert else we can update
			var isNew = doc == undefined
			doc = doc || {cid: cid}

			//  at first we will collect agent name
			if (packet.browser_cname) {
				doc.agent_name = doc.agent_name || []
				// check if it already exits or not
				if (doc.agent_name.indexOf(packet.browser_cname) == -1) {
					doc.agent_name.push(packet.browser_cname)
				}
			}

			
			// now its time to save the doc
			if (isNew) {
				db.insert(doc)
			}
			else {
				db.update({cid: cid}, doc)
			}
		})
	}
	else if (packet.protos.indexOf('bootp') != -1) {
		// so this is bootp packet we can get
		// information about host name, vendor class id
		// but first we need to get doc
		// for given cid
		db.findOne({cid: cid}, function (err, doc) {
			// check if doc exits or not
			// if not then we might need to insert else we can update
			var isNew = doc == undefined
			doc = doc || {cid: cid}

			//  at first we will collect agent name
			if (packet.bootp_hostname) {
				doc.agent_name = doc.agent_name || []
				// check if it already exits or not
				if (doc.agent_name.indexOf(packet.bootp_hostname) == -1) {
					doc.agent_name.push(packet.bootp_hostname)
				}
			}

			//  then if there is any vendor class ID
			// then save it also
			if (packet.bootp_vendorclassid) {
				doc.vendor_classid = doc.bootp_vendorclassid || []
				// check if it already exits or not
				if (doc.vendor_classid.indexOf(packet.bootp_vendorclassid) == -1) {
					doc.vendor_classid.push(packet.bootp_vendorclassid)
				}
			}
			

			// now its time to save the doc
			if (isNew) {
				db.insert(doc)
			}
			else {
				db.update({cid: cid}, doc)
			}
		})
	}
}


// genrates a CID for a given packet which help us identify which network device it belongs to
function genCID (packet) {
	var mac = packet.protos.indexOf('wlan') != -1 ? packet.sender_address_mac : packet.eth_src
	var ip = packet.src_ip
	if (ip == undefined || ip == '0.0.0.0' || ip == '255.255.255.255') {
		return undefined
	}
	if (mac == undefined || mac == '000000000000') {
		return undefined
	}
	return mac + '@' + ip		
}