/** @fileOverview session negotiation
 *
 *
 * @author Kyle Graehl
 * @author Aseem Mohanty
 **/

BigInteger.prototype.toPaddedHex = function(paddedLength) {
    var hex = this.toString(16);
    while (hex.length < paddedLength)
        hex = "0" + hex;
    return hex;
}

BigInteger.prototype.toAscii = function(expectedLengthInCharacters) {
    var out = '';
    var hex = this.toPaddedHex(expectedLengthInCharacters);
    for (var i = 0, ii = hex.length; i < ii; i += 2)
    out += String.fromCharCode(parseInt(hex.charAt(i) + hex.charAt(i + 1), 16));
    return out;
}

for (var i=0;i<1000;i++) {
    // seed with something better please!
    sjcl.random.addEntropy(Math.random(), 2);
}

/**
 * @class a falcon remote session
 * create a new falcon session
 */
falcon.session = function(options) {
    this.callbacks = {
        invalidated: []
    };
    this.api = null;
    this._token_fetching = false;
    this._token_fetched = false;
    this._token_fetch_fail = false;
    this._token_fetch_fail_data = null;
    this._pending_requests = [];

    this.options = options || {};
    if (options && options.client_data) {
	this.api = new falcon.api(options.client_data);
    }
}

falcon.session.prototype = {
    request: function(uri, url_params, body_params, callback, errback, opts) {
        var prefix = this.options.direct ? '' : '/client';
        if (! this._token_fetched && ! uri.match('/gui/token.html')) {
            if (! this._token_fetching) {
                console.log('fetching token');
                var token_url = prefix + '/gui/token.html';
                this.api.request('GET', token_url, {}, {t:0}, _.bind(this.token_fetched,this), _.bind(this.token_fetch_fail, this));
                this._token_fetching = true;
            }
            var thislater = _.bind(this.request, this, uri, url_params, body_params, callback, errback, opts);
            this._pending_requests.push(thislater);
        } else {
            if (this._token_fetch_fail) {
                var data = this._token_fetch_fail_data;
                errback(data.xhr, data.status, data.text);
            } else {
                this.api.request( 'GET', prefix + uri, url_params, body_params, callback, errback, opts );
            }
        }
    },
    token_fetch_fail: function(xhr, status, text) {
        this._token_fetched = true;
        this._token_fetch_fail = true;
        this._token_fetch_fail_data = { xhr: xhr, status: status, text: text };
        this._token_fetching = false;
        _.each( this._pending_requests, function(req) { req(); } );
        this._pending_requests = [];
    },
    token_fetched: function(resp) {
        this._token_fetched = true;
        this._token_fetching = false;
        _.each( this._pending_requests, function(req) { req(); } );
        this._pending_requests = [];
    },
    /** @private **/
    set_progress_range: function(low, hi, pct) {
        var width = Math.min((hi-low)*pct+low, hi);
        this.set_progress(width);
    },
    /** @private **/
    set_progress: function(amount) {
        if (this.options && this.options.progress) {
            this.options.progress( { 'progress': amount } );
        } else {
            console.log('progress',amount);
        }
    },
    /** @private **/
    set_label: function(message) {
        if (this.options && this.options.progress) {
            this.options.progress( { 'message': message } );
        } else {
            console.log('label',message);
        }
    },
    /** @private **/
    error_out: function(xhr, status, text) {
        console.error('error in key negotiation', status, text);
        if (this.options && this.options.error) { 
            return this.options.error(xhr, status, text);
        } else {
            alert('failure negotiating: ' + text);
        }
    },
    /** @private **/
    jsonp_error: function(xhr, status, text) {
        // uncatchable jsonp error
        debugger;
        this.error_out(xhr, status, text);
    },
    check_username: function(username, options) {
        jQuery.ajax( { url: config.srp_root + '/api/exists?username=' + encodeURIComponent(username),
                       success: options.success,
                       error: options.error,
                       dataType: 'jsonp'
                     });
    },
    /** @private **/
    get_srp_url: function(data, newsession) {
        if (this.options.direct) {
            var url = 'http://' + this.options.direct + '/gui/srp/';
        } else {
            var url = config.srp_root + '/api/login/'; // needs trailing slash
        }

        if (newsession) {
            url = url + '?new=1';
        } else if (this.guid) {
            url = url + '?GUID=' + encodeURIComponent(this.guid);
        } else {
            throw new falcon.exception.invalid('no session id');
        }
        for (var key in data) {
            url = url + '&' + encodeURIComponent(key) + '=' + encodeURIComponent( data[key] );
        }
        return url;
    },
    /** negotiate an encryption key with the remote client
     * @param String username
     * @param String password
     * @param Object negotiation options. Pass in "success" "error" callback functions.
     *  **/
    negotiate: function(username, password, options) {
        _.extend( this.options, options );
        this.credentials = {username: username, password: password};
        this.username = username;
        var data = {
            user: username
        };

	this.set_label('Sending computer name');

        jQuery.ajax(this.get_srp_url(data, true), { 
                        dataType: 'jsonp',
                        cached: false,
            timeout: (options && options.timeout),
                        error: _.bind(this.jsonp_error, this),
                        success: _.bind(this.create_public_key, this) } );
    },
    /** pass in a function that will be called when the client no
     * longer recognizes the encrypted session
     * @param Function callback
     */
    add_invalidated_callback: function(callback) {
        this.callbacks.invalidated.push(callback);
    },
    /** @private **/
    create_public_key: function(data, status, xhr) {
        if (data.error) {
            console.error('error getting generator', data);
            return this.error_out(xhr, status, data);
        }
        this.guid = data.guid;
        var response = data.response || data;

        if (! response.length || response.length != 3) {
            console.error('public key response makes no sense', response);
            return this.error_out(xhr, status, 'public key response bad');
        }

        this.set_progress(.3);
        this.set_label("Creating public key...");
        this.modulus = new BigInteger(response[0], 10);
        this.generator = new BigInteger(response[1], 10);
        this.salt = new BigInteger(response[2], 10);
        this.exponent = new BigInteger(sjcl.codec.hex.fromBits(sjcl.random.randomWords(5)), 16);
        if (window.jQuery && jQuery.jStorage) {
            jQuery.jStorage.set('entropySeed', sjcl.random.randomWords(9));
        }
        var _this = this;
        function progress_fn(pct) {
            return _this.set_progress_range(0.3, 0.45, pct);
        }
        this.generator.modPow(this.exponent, this.modulus, _.bind(this.created_public_key, this), progress_fn);
    },
    /** @private **/
    created_public_key: function(public_key) {
        this.public_key = public_key;
        var data = {
            username: this.username,
            pub: public_key.toString(10),
            time: new Date().getTime()
        };
	console.log(this.get_srp_url(data));
        jQuery.ajax(this.get_srp_url(data), { dataType: 'jsonp',
                                              cached: false,
                                              error: _.bind(this.jsonp_error, this),
                                              success: _.bind(this.sent_public_key, this) } );
    },
    /** @private **/
    sent_public_key: function(data, status, xhr) {
        // this should not be an anonymous function!
        if (data.error)  {
            console.error('error',data);
            this.error_out( xhr, status, data );
            return;
        }
        var response = data.response;
        this.create_session_key(xhr, status, new BigInteger(response[0], 10), this.modulus, this.generator, this.salt, this.exponent);
    },
    /** @private **/
    create_session_key: function(xhr, status, server_key, modulus, generator, salt, exponent) {
        this.set_progress(.45);
        this.set_label("Creating session key...");

        this.server_key = server_key;
        // We abort the protocol here if B == 0 (mod N).
        if (0 == this.server_key.modPow(new BigInteger("1", 10), this.modulus)) {
            this.error_out(xhr, status, "The client provided an invalid public key. " + server_key + "Please try again.");
        }

        var kay = new BigInteger("3", 10);
        var u = new BigInteger(
            sha1Hash(this.public_key.toAscii(320) + this.server_key.toAscii(320)), 16);

        // We abort the protocol here if u == 0.
        var _this = this;
        u.modPow(new BigInteger("1", 10), this.modulus, function(result) {
                     if (0 == result) {
                         alert("The client provided an invalid exponent (\"u\"). " + "Please try again.");
                         throw "Server provided a \"u\" parameter which was = 0 mod N. " + "Aborting SRP process.";
                     }
                 });
        var username = jQuery('#username').val() || this.credentials.username;
        var password = jQuery('#password').val() || this.credentials.password;
        this.credentials = null;
        var usernameAndPassword = username + ':' + password;
        var usernameAndPasswordHash = sha1Hash(usernameAndPassword);
        var usernameAndPasswordInt = new BigInteger(usernameAndPasswordHash, 16);
        password = new BigInteger(
            sha1Hash(salt.toAscii(20) + usernameAndPasswordInt.toAscii(usernameAndPasswordHash.length)), 16);

        function progress_fn(pct) {
            return _this.set_progress_range(0.45, 0.7, pct);
        }
        function progress_fn2(pct) {
            return _this.set_progress_range(0.7, 0.95, pct);
        }
        generator.modPow(password, modulus, function(g_to_the_x) {
                             negative_g_to_the_x = modulus.subtract(g_to_the_x);
                             negative_g_to_the_x_times_k = negative_g_to_the_x.multiply(kay);
                             _this.server_key.add(negative_g_to_the_x_times_k).modPow(
                                 new BigInteger("1", 10), modulus, function(key_base) {
                                     key_exponent = exponent.add(u.multiply(password));
                                     key_base.modPow(key_exponent, modulus, function(client_num) {
                                                         //jQuery.debug("client_num ('pre-key'): " + client_num.toString(10));
                                                         client_hash = sha1Hash(client_num.toAscii(320));
                                                         _this.client_key = new BigInteger(client_hash, 16);
							 _this.client_key_str = _this.client_key.toPaddedHex(40).slice(0, 40);
                                                         // We only want the first 16 bytes of the key because we're only
                                                         // using AES-128.
                                                         _this.verify_key();
                                                     }, progress_fn2);
                                 });
                         }, progress_fn);
    },
    /** @private **/
    compute_verify_key_one: function() { /* M1 = H(H(N) XOR H(g) | H(l) | s | A | B | KCarol) */

        //this.set_progress(.8);
        this.set_label("Sending key verifier");

        var xor_term = new BigInteger(sha1Hash(this.modulus.toAscii(320)), 16).xor(new BigInteger(sha1Hash(
                                                                                                      this.generator.toAscii(2)), 16));
        var A = this.public_key;
        var B = this.server_key;

        var M1_pre_hash = xor_term.toAscii(40) + new BigInteger(
            sha1Hash(this.username), 16).toAscii(40) + this.salt.toAscii(20) + A.toAscii(320) + B.toAscii(320) + this.client_key.toAscii(40);
        var M1 = sha1Hash(M1_pre_hash);
        this.M1 = new BigInteger(M1, 16);
        return this.M1.toString(10);
    },
    /** @private **/
    compute_verify_key_two: function() { /* M2 = H(A | M1 | KSteve) */
        var A = this.public_key;

        //this.set_progress(.9);
        this.set_label("Verifying key ...");

        var M2 = sha1Hash(A.toAscii(320) + this.M1.toAscii(40) + this.client_key.toAscii(40));
        return new BigInteger(M2, 16).toString(10);
    },
    // Confusingly, we run verify using "client_key," which is the full 20-byte
    // SHA-1 hash, but we use the 16-byte prefix, "key," as the actual AES key,
    // since we're using AES-128.
    /** @private **/
    verify_key: function() {
        var _this = this;
        if (window.eventTracker) eventTracker.track('Login', 'SendVerify');
        var data =         {
            username: _this.username,
            verify: _this.compute_verify_key_one(),
            time: new Date().getTime()
        };
        jQuery.ajax(_this.get_srp_url(data), { dataType: 'jsonp',
                                               cached: false,
                                               error: _.bind(this.jsonp_error, this),
                                               success: _.bind(this.got_key_verify, this) } );
    },
    /** @private **/
    got_key_verify: function(data, status, xhr) {
        var _this = this;
        if (data.error)  {
            console.error('error',data);
            this.error_out( xhr, status, data );
            return;
        }
        var response = data.response;

        var M2 = response[0];
        if (M2 == _this.compute_verify_key_two()) {
            _this.set_progress(1);
            _this.set_label("Verification complete!");

            var tkt = data.bt_talon_tkt;
            if (this.options && this.options.direct) {
                var client_data = { key: this.client_key_str,
                                    guid: this.guid,
                                    direct: this.options.direct
                                  };
            } else if (tkt) {
                var guid = _this.guid;
                var client_data = { key: this.client_key_str,
                                    bt_talon_tkt: tkt,
                                    port: data.port,
                                    bt_user: _this.username,
                                    cid: data.cid,
                                    host: data.host,
                                    ip: data.ip,
                                    guid: guid,
                                    agent: data.agent,
				    api: '2.1'
                                  };
            }
            console.log('log in success with client data',client_data);
            var api = new falcon.api(client_data);
            _this.api = api;
            if (this.options && this.options.success) {
                this.clear();
                this.options.success( this );
            }

        } else {
            _this.error_out(xhr, status, "Password invalid");
        }
    },
    serialize: function() {
	return this.api.client_data;
    },
    clear: function() {
        // clear intermediate negotiation stuff
        delete this.M1;
        delete this.client_key;
        delete this.client_key_str;
        delete this.exponent;
        delete this.generator;
        delete this.guid;
        delete this.modulus;
        delete this.public_key;
        delete this.salt;
        delete this.server_key;
        delete this.username;
    }
}