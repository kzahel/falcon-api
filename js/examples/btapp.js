
function doreq() {
        session.request('/gui/', {list:1}, {}, function(r) { console.log('got resp',r);} );
}

function done() {
    doreq();
    setInterval( doreq
                 , 4000 );
}

var session = new falcon.session();
session.negotiate('kylepoo9','pass', { success: done } );
