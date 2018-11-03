const pcap = require( 'pcap' )
const HTTPFromPCAP = require( '.' )

const pcapSession = pcap.createSession( 'lo0', 'tcp port 80' )

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
