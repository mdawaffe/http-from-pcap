#!/usr/bin/env node

const fs = require( 'fs' )
const path = require( 'path' )
const { format } = require( 'util' )

const chalk = require( 'chalk' )
const pcap = require( 'pcap' )
const HTTPFromPCAP = require( '.' )

const deviceOrPath = process.argv[2] || false
const prettify = process.argv.includes( '--pretty' )
const showBody = prettify || process.argv.includes( '--body' )

const filter = 'ip proto \\tcp and port 80'

function help() {
	const bin = path.basename( process.argv[1] )

	return `
${bin} DEVICE
${bin} PATH_TO_PCAP_DUMP_FILE

Arguments:
	--body   Show HTTP Message Bodies.
	--pretty Reformat HTTP Message Bodies prettily (JSON). Implies --body
`
}

let pcapSession
if ( pcap.findalldevs().map( device => device.name ).includes( deviceOrPath ) ) {
	pcapSession = pcap.createSession( deviceOrPath, filter )
} else if ( '-' === deviceOrPath || fs.existsSync( deviceOrPath ) ) {
	pcapSession = pcap.createOfflineSession( deviceOrPath, filter )
} else {
	console.error( help() )
	process.exit( 1 )
}

const httpFromPCAP = new HTTPFromPCAP( pcapSession, { trackBodies: showBody } )

function headerFromRawHeaders( rawHeaders ) {
	return rawHeaders
		.map( ( part, i, all ) => [ part, all[i+1] || false ] )
		.filter( ( header, i ) => !( i % 2 ) )
		.map( ( [ k, v ] ) => `${k}: ${v}` )
		.join( '\n' )
}

function prettifyMessage( message ) {
	const contentType = message.headers['content-type'] || ''

	const body = message.chunks

	// @todo?
	if ( ! ( ~ contentType.indexOf( 'json' ) ) ) {
		return body
	}

	try {
		const serialized = body.reduce( ( serialized, chunk ) => serialized + chunk.toString( 'utf8' ), '' )
		const object = JSON.parse( serialized )
		return [ Buffer.from( JSON.stringify( object, null, '  ' ), 'utf8' ) ]
	} catch ( err ) {
		return body
	}
}

function displayMessage( header, message ) {
	header += '\n' + chalk.blue( headerFromRawHeaders( message.rawHeaders ) ) + '\n'

	if ( showBody ) {
		const body = prettify ? prettifyMessage( message ) : message.chunks

		if ( body ) {
			console.log( header + '\n' )
			for ( const chunk of body ) {
				process.stdout.write( chunk )
			}
			console.log( '\n' )
		} else {
			console.log( header + '\n' )
		}
	} else {
		console.log( header )
	}
}

httpFromPCAP.on( 'http', http => {
	http.on( 'request message', request => {
		const header
			= format( chalk.bold( '%s -> %s' ), request.src, request.dst ) + '\n'
			+ format( chalk.blue.bold( '%s %s HTTP/%s' ), request.method, request.url, request.httpVersion )
		displayMessage( header, request )
	} )

	http.on( 'response message', response => {
		const header
			= format( chalk.bold( '%s <- %s' ), response.src, response.dst ) + '\n'
			+ format( chalk.blue.bold( 'HTTP/%s %d %s' ), response.httpVersion, response.statusCode, response.statusMessage )
		displayMessage( header, response )
	} )
} )
