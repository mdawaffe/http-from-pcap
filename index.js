'use strict'

const { methods, HTTPParser } = process.binding( 'http_parser' ) // may have to replace with https://github.com/creationix/http-parser-js
const { freeParser } = require( '_http_common' )

const EventEmitter = require( 'events' )
const { Readable } = require( 'stream' )

const pcap = require( 'pcap' )

class HTTPFromPCAP extends EventEmitter {
	constructor( pcapSession ) {
		super()

		this.tcpTracker = new pcap.TCPTracker()

		this.tcpTracker.on( 'session', session => {
			this.emit( 'http', new HTTPFromTCP( session ) )
		} )

		pcapSession.on( 'packet', raw => {
			const packet = pcap.decode.packet( raw )
			this.tcpTracker.track_packet( packet )
		} )
	}
}

class HTTPMessage extends Readable {
	constructor( type, src, dst, isn ) {
		super()

		this.parser = new HTTPParser( type )
		this.src = src
		this.dst = dst
		this.isn = isn

		this.chunks = []

		this.httpVersion = ''
		this.url = ''
		this.rawHeaders = []
		this.headers = {}

		this.parser[HTTPParser.kOnHeaders] = this.onHeaders.bind( this )
		this.parser[HTTPParser.kOnHeadersComplete] = this._onHeadersComplete.bind( this )
		this.parser[HTTPParser.kOnBody] = this.onBody.bind( this )
		this.parser[HTTPParser.kOnMessageComplete] = this.onMessageComplete.bind( this )
		this.parser[HTTPParser.kOnExecute] = this.onExecute.bind( this )
	}

	onHeaders( rawHeaders = [], url = '' ) {
		this.rawHeaders = this.rawHeaders.concat( rawHeaders )
		this.url += url
	}

	_onHeadersComplete( versionMajor, versionMinor, rawHeaders, method, url, statusCode, statusMessage, upgrade, shouldKeepAlive ) {
		this.httpVersion = versionMajor + '.' + versionMinor

		this.rawHeaders = rawHeaders || this.rawHeaders
		let headers = {}
		for ( let i = 0, l = rawHeaders.length; i < l; i +=2 ) {
			headers[rawHeaders[i].toLowerCase()] = rawHeaders[i + 1]
		}

		this.headers = headers
		this.url = url || this.url

		this.onHeadersComplete( { versionMajor, versionMinor, rawHeaders, method, url, statusCode, statusMessage, upgrade, shouldKeepAlive } )

		this.emit( 'http headers', this )
	}

	onHeadersComplete( info ) {}

	onBody( buffer, start, length ) {
		const chunk = Buffer.from( buffer.slice( start, start + length ) )
		this.chunks.push( chunk )
	}

	onMessageComplete() {
		this.chunks.push( null )
		this.emit( 'http message', this )
	}

	onExecute( ...args ) {
		console.log( 'execute', args )
	}

	free() {
		freeParser( this.parser )
	}

	_read( size ) {
		let more = false
		do {
			const chunk = this.chunks.shift()
			if ( 'undefined' === typeof chunk ) {
				break
			}

			more = this.push( chunk )
		} while ( more )
	}
}

class HTTPRequest extends HTTPMessage {
	constructor( { src, dst, isn } ) {
		super( HTTPParser.REQUEST, src, dst, isn )

		this.method = ''
	}

	onHeadersComplete( info ) {
		this.method = methods[info.method]
	}
}

class HTTPResponse extends HTTPMessage {
	constructor( { src, dst, isn } ) {
		super( HTTPParser.RESPONSE, src, dst, isn )

		this.statusCode = 0
		this.statusMessage = ''
	}

	onHeadersComplete( info ) {
		this.statusCode = info.statusCode
		this.statusMessage = info.statusMessage
	}
}

class HTTPFromTCP extends EventEmitter {
	constructor( tcpSession ) {
		super()

		const request = new HTTPRequest( {
			src: tcpSession.src_name,
			dst: tcpSession.dst_name,
			isn: tcpSession.send_isn,
		} )

		request.on( 'http headers', request => {
			this.emit( 'request headers', request )
		} )
		request.on( 'http message', request => {
			this.emit( 'request message', request )
		} )

		tcpSession.on( 'data send', ( session, data ) => {
			request.parser.execute( data, 0, data.length )
		} )


		const response = new HTTPResponse( {
			src: tcpSession.src_name,
			dst: tcpSession.dst_name,
			isn: tcpSession.send_isn,
		} )

		response.on( 'http headers', response => {
			this.emit( 'response headers', response )
		} )
		response.on( 'http message', response => {
			this.emit( 'response message', response )
		} )

		tcpSession.on( 'data recv', ( session, data ) => {
			response.parser.execute( data, 0, data.length )
		} )


		tcpSession.on( 'end', () => {
			request.free()
			response.free()
		} )
	}
}

module.exports = HTTPFromPCAP
