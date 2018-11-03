#!/usr/bin/env node

const fs = require( 'fs' )
const path = require( 'path' )
const { pipeline, Transform, Readable, PassThrough } = require( 'stream' )
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
} else if ( fs.existsSync( deviceOrPath ) ) {
	pcapSession = pcap.createOfflineSession( deviceOrPath, filter )
} else {
	console.error( help() )
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

class PrettifyMessage extends Transform {
	constructor( message ) {
		super()

		this.chunks = []

		this.contentType = message.headers['content-type'] || ''

		// @todo?
		if ( ~ this.contentType.indexOf( 'json' ) ) {
			this._transform = this._transform_json.bind( this )
			this._flush = this._flush_json.bind( this )
		} else {
			this._transform = this._transform_noop.bind( this )
		}
	}

	_transform_noop( chunk, encoding, callback ) {
		callback( null, chunk )
	}

	_transform_json( chunk, encoding, callback ) {
		this.chunks.push( chunk )
		callback()
	}

	_flush_json( callback ) {
		try {
			const serialized = this.chunks.reduce( ( serialized, chunk ) => serialized + chunk.toString( 'utf-8' ), '' )
			const object = JSON.parse( serialized )
			this.push( JSON.stringify( object, null, '  ' ) )
		} catch( err ) {
			return callback( err )
		}

		callback()
	}
}

async function displayMessage( header, message ) {
	header += '\n' + chalk.blue( headerFromRawHeaders( message.rawHeaders ) ) + '\n'

	if ( showBody ) {
		const streams = [ message, prettify ? new PrettifyMessage( message ) : new PassThrough ]

		const bodyReadable = pipeline( streams, err => {
			if ( err ) {
				return console.error( err )
			}

			const chunks = []
			bodyReadable.on( 'data', chunk => {
				chunks.push( chunk )
			} )

			bodyReadable.on( 'end', () => {
				const body = chunks.map( chunk => chunk.toString() ).join( '' )
				if ( body ) {
					console.log( header + '\n' + body + '\n' )
				} else {
					console.log( header + '\n' )
				}
			} )
		} )
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
