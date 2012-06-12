
function doreq() {
    session.request('/gui/', null, {list:1}, function(r) { console.log('got resp',r);} );
}

function done() {
    doreq();
    setInterval( doreq
                 , 4000 );
}

function err(xhr, status, text) {
    console.log('negotiate error',xhr,status,text);
}


var session = new falcon.session( { direct: '192.168.56.101:36440',
                                  } );
//var session = new falcon.session();
session.negotiate('foofoo8','pass', { success: done,
                                       error: err} );
