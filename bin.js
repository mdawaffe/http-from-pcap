#!/usr/bin/env node

const fs = require( 'fs' )
const path = require( 'path' )

const pcap = require( 'pcap' )
const HTTPFromPCAP = require( '.' )

const deviceOrPath = process.argv[2] || false

const filter = 'ip proto \\tcp and port 80'

let pcapSession
if ( pcap.findalldevs().map( device => device.name ).includes( deviceOrPath ) ) {
	pcapSession = pcap.createSession( deviceOrPath, filter )
} else if ( fs.existsSync( deviceOrPath ) ) {
	pcapSession = pcap.createOfflineSession( deviceOrPath, filter )
} else {
	const bin = path.basename( process.argv[1] )
	console.error( `${bin} DEVICE\n${bin} PATH_TO_PCAP_DUMP_FILE` )
	process.exit( 1 )
}

const httpFromPCAP = new HTTPFromPCAP( pcapSession )

httpFromPCAP.on( 'http', http => {
	http.on( 'request headers', request => {
		console.log( 'REQUEST: ', request )
	} )
	http.on( 'request message', request => {
		request.pipe( process.stderr )
	} )

	http.on( 'response headers', response => {
		console.log( 'RESPONSE:', response )
	} )
	http.on( 'response message', response => {
		response.pipe( process.stderr )
	} )
} )
