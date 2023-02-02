"use strict";

// This file contains all the javascript that's not directly crypto or storage
// That is, code that cannot go wrong

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

    if(VAULT.exists(secretname)) {
        alert('A secret named "'+secretname+'" already exists.');
        return;
    }

    const secret = CRYPTO.KEX.derive(otherpubkey);
    VAULT.save(secretname, secret);
    updateSecrets();
    $('#secretname')[0].value = '';
    $('#otherpubkey')[0].value = '';
}

function updateSecrets() {
    const sel = $('select');
    sel.html('');
    sel[0].disabled = false;

    const secrets = VAULT.getSecrets();
    for(const entry of secrets) {
        const newitem = $('<option>');
        newitem.text(entry[0]);
        sel.append(newitem);
    }

    if(secrets.length === 0) {
        sel.append($('<option>No keys yet.</option>'));
        sel[0].disabled = true;
    }
}

function getAES() {
    const name = $('select')[0].value;
    const hex = VAULT.get(name);
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

function selectSecret(secret) {
    let i = 0;
    for(const entry of VAULT.getSecrets()) {
        if(entry[1] === secret) {
            $('select').children()[i].selected = true;
            $('select').click();
            break;
        }
        ++i;
    }
}

$(document).ready(() => {
    // Generate a key pair if it's not there.
    if(!VAULT.hasKeypair()) {
        let pub, priv = CRYPTO.KEX.genKeyPair();
        VAULT.saveMyKeys(pub, priv);
    } else {
        CRYPTO.KEX.restoreKey(VAULT.getPriv());
    }
    $('#mypubkey').text(VAULT.getPub());

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

    // Alice's key in URL?
    const query = window.location.search;
    const params = new URLSearchParams(query);
    const alice = params.get('alice');
    const alicekey = params.get('key');
    if(alice !== null && alicekey !== null) {
        if(/^\w+$/.test(alice) && /^[0-9a-fA-F]+$/.test(alicekey)) {
            // Is alicekey already there?
            const secret = CRYPTO.KEX.derive(alicekey);
            if(VAULT.hasSecret(secret)) {
                // Already there, just select it
                selectSecret(secret);
            } else {
                // New secret!
                $('#fromlink').css("display", "block");
                $('#alicename').text(alice);
                console.log(secret);

                $('#addalice').click(() => {
                    VAULT.save(alice, secret);
                    updateSecrets();
                    $('#fromlink').css("display", "none");
                    // And select it too
                    selectSecret(secret);
                });
            }
        }
    }
});
