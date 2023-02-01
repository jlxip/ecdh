"use strict";

const ec = new elliptic.ec('curve25519');
var key = null;

function derive() {
    const secretname = $('#secretname')[0].value;
    const otherpubkey = $('#otherpubkey')[0].value;
    if(!secretname.length) {
        // TODO: Make the input red.
        alert('You have to give the secret a name.');
        return;
    }
    if(!otherpubkey.length) {
        alert('You have not introduced a public key.');
        return;
    }

    if(localStorage.getItem('S'+secretname)) {
        alert('A secret named "'+secretname+'" already exists.');
        return;
    }

    let other;
    try {
        other = ec.keyFromPublic(otherpubkey, 'hex').getPublic();
    } catch(e) {
        alert('Invalid key.');
        return;
    }

    const secret = key.derive(other).toString(16);
    localStorage.setItem('S'+secretname, secret);
    updateSecrets();
    $('#secretname')[0].value = '';
    $('#otherpubkey')[0].value = '';
}

function updateSecrets() {
    const sel = $('select');
    sel.html('');
    sel[0].disabled = false;

    var any = false;
    const names = Object.keys(localStorage).sort();
    for(const n of names) {
        if(n[0] == 'S') {
            any = true;

            const name = n.substr(1);
            const newitem = $('<option>');
            newitem.text(name);
            sel.append(newitem);
        }
    }

    if(!any) {
        sel.append($('<option>No keys yet.</option>'));
        sel[0].disabled = true;
    }
}

function getAES() {
    const name = $('select')[0].value;
    const hex = localStorage.getItem('S'+name);
    if(!hex) {
        alert('Something went awfully wrong.');
        return false;
    }
    const key = sjcl.codec.hex.toBits(hex);
    return new sjcl.cipher.aes(key);
}

const IV_WORDS = 3; // 3 words * 4 bytes/word * 8 bits/byte = 96 bits

function encrypt() {
    const aes = getAES();
    if(!aes) return;

    const contents = sjcl.codec.utf8String.toBits($('#input')[0].value);
    const iv = sjcl.random.randomWords(IV_WORDS);
    const enc = sjcl.mode.gcm.encrypt(aes, contents, iv);
    const both = iv.concat(enc);
    const ret = sjcl.codec.base64.fromBits(both);

    $('#output').text(ret);
}

function decrypt() {
    const aes = getAES();
    if(!aes) return;

    let contents;
    try {
        contents = sjcl.codec.base64.toBits($('#input')[0].value);
    } catch(e) {
        alert('Input is not base64.');
        return;
    }

    const iv = contents.slice(0, IV_WORDS);
    const enc = contents.slice(IV_WORDS);

    let dec;
    try {
        dec = sjcl.mode.gcm.decrypt(aes, enc, iv);
    } catch(e) {
        alert('Error decrypting.');
        return;
    }

    const ret = sjcl.codec.utf8String.fromBits(dec);

    $('#output').text(ret);
}

$(document).ready(() => {
    // Generate a key pair if it's not there.
    if(!localStorage.getItem('pub')) {
        key = ec.genKeyPair();
        localStorage.setItem('pub', key.getPublic('hex'));
        localStorage.setItem('priv', key.getPrivate('hex'));
    } else {
        key = ec.keyFromPrivate(localStorage.getItem('priv'));
    }
    $('#mypubkey').text(localStorage.getItem('pub'));

    $('#derive').click(derive);
    $('select').click(() => {
        if($('select')[0].value !== '') {
            $('#encdec *').attr('disabled', false);
        }
    });
    $('#encdec *').attr('disabled', true);
    $('#encrypt').click(encrypt);
    $('#decrypt').click(decrypt);
    updateSecrets();

    new ClipboardJS('#copypub');
    new ClipboardJS('#copyresult');

    // I hate this in every possible aspect.
    $('#uglyresize').width($('#input').width() - $('#copyresult').width())
});
