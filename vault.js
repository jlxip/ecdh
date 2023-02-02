"use strict";

// This file contains an abstraction over "localStorage", which is slightly
// simpler in this scenario

// Namespace
var VAULT = {
    saveMyKeys: function(pub, priv) {
        localStorage.setItem('pub', pub);
        localStorage.setItem('priv', priv);
    },
    getPub: function() {
        return localStorage.getItem('pub');
    },
    getPriv: function() {
        return localStorage.getItem('priv');
    },
    hasKeypair: function() {
        return this.getPub() !== null;
    },



    get: function(name) {
        return localStorage.getItem('S'+name);
    },
    exists: function(name) {
        return this.get(name) !== null;
    },
    hasSecret: function(secret) {
        for(const n of Object.keys(localStorage)) {
            if(localStorage.getItem(n) === secret) {
                return true;
            }
        }

        return false;
    },
    save: function(name, secret) {
        localStorage.setItem('S'+name, secret);
    },
    getSecrets: function() {
        let ret = [];
        const names = Object.keys(localStorage).sort();
        for(const n of names) {
            if(n[0] === 'S') {
                ret.push([n.substr(1), localStorage.getItem(n)]);
            }
        }
        return ret;
    }
};
