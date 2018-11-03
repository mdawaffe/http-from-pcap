#!/usr/bin/env node

const fs = require( 'fs' )
const path = require( 'path' )

const chalk = require( 'chalk' )
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

function headerFromRawHeaders( rawHeaders ) {
	return rawHeaders
		.map( ( part, i, all ) => [ part, all[i+1] || false ] )
		.filter( ( header, i ) => !( i % 2 ) )
		.map( ( [ k, v ] ) => `${k}: ${v}` )
		.join( '\n' )
}


// @TODO: need to serialize these writes
httpFromPCAP.on( 'http', http => {
	http.on( 'request message', request => {
		console.log( chalk.bold( '%s -> %s' ), request.src, request.dst )
		console.log( chalk.blue.bold( '%s %s HTTP/%s' ), request.method, request.url, request.httpVersion )
		console.log( chalk.blue( headerFromRawHeaders( request.rawHeaders ) ) )
		console.log()
		request.pipe( process.stdout )
	} )

	http.on( 'response message', response => {
		console.log( chalk.bold( '%s <- %s' ), response.src, response.dst )
		console.log( chalk.blue.bold( 'HTTP/%s %d %s' ), response.httpVersion, response.statusCode, response.statusMessage )
		console.log( chalk.blue( headerFromRawHeaders( response.rawHeaders ) ) )
		console.log()
		response.pipe( process.stdout )
	} )
} )
