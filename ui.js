"use strict";

// This file contains all the javascript that's not directly crypto
// That is, code that cannot go wrong
// This includes handling the local storage

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

    const secret = CRYPTO.KEX.derive(otherpubkey);
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
    if(!hex)
        throw new Error('Something went awfully wrong.');
    return CRYPTO.AE.getAES(hex);
}

function encrypt() {
    const aes = getAES();
    const contents = $('#input')[0].value;
    const enc = CRYPTO.AE.encrypt(aes, contents);
    $('#output').text(enc);
}

function decrypt() {
    const aes = getAES();
    const encoded = $('#input')[0].value;
    const dec = CRYPTO.AE.decrypt(aes, encoded);
    $('#output').text(dec);
}

$(document).ready(() => {
    // Generate a key pair if it's not there.
    if(!localStorage.getItem('pub')) {
        let pub, priv = CRYPTO.KEX.genKeyPair();
        localStorage.setItem('pub', pub);
        localStorage.setItem('priv', priv);
    } else {
        CRYPTO.KEX.restoreKey(localStorage.getItem('priv'));
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
