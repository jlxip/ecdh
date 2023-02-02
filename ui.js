"use strict";

// This file contains all the javascript that's not directly crypto or storage
// That is, code that cannot go wrong

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

    const yourlink = window.location.href.split('?')[0] +
          "?key="+VAULT.getPub();
    $('#mypubkey')[0].value = yourlink;
    $('#mypubkey')[0].size = yourlink.length;

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

    // Alice's key in URL?
    const query = window.location.search;
    const params = new URLSearchParams(query);
    const alicekey = params.get('key');
    if(alicekey !== null) {
        if(/^[0-9a-fA-F]+$/.test(alicekey)) {
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
                    const alice = $('#alice')[0].value;
                    if(!alice.length) {
                        alert('You have to give this shared secret a name');
                        return;
                    } else if(VAULT.exists(alice)) {
                        alert('A secret named "'+alice+'" already exists');
                        return;
                    }

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
