/** @fileOverview BitTorrent Falcon javascript library
 *
 * @author Kyle Graehl
 */

if (! window._) {
    console.error('require underscore.js');
}
if (! window.jQuery) {
    console.error('require jquery');
}



var falcon_config = {
    srp_root: 'https://remote.utorrent.com'
//    srp_root: 'http://10.10.90.24:9090'
//    srp_root: 'http://192.168.56.1:9090'
//    srp_root: 'http://remote-staging.utorrent.com'
};


if (! window.config) {
    window.config = falcon_config;
} else {
    for (var key in falcon_config) {
        window.config[key] = falcon_config[key];
    }
}


/** @namespace Falcon remote api namespace. */
var falcon = {
};