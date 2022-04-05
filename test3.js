var qryDomain = "test3.XXXXX";   
var baseDomain = ".XXXXX";                                                                                             

var idCampaign = "YYYYY";
var startAdTime = new Date().getTime();
var idAd = new Date().valueOf() + Math.random().toFixed(8).substring(2);
var referrer = "not";
var url = "not";
if (document.referrer) referrer = document.referrer;
if (document.URL) url = document.URL;
var language = navigator.language;
var platform = navigator.platform;
var userAgent = navigator.userAgent;
var screen_height = window.screen.availHeight;
var screen_width = window.screen.availWidth;

var dnsJsonHeaders = new Headers();
dnsJsonHeaders.append("accept", "application/dns-json");

var dnsRequestConf = {
  method: "GET",
  headers: dnsJsonHeaders,
  mode: "cors",
  cache: "default",
};

var dataBuffer = []
var sentQueries = []
var obsCount = 0;
var socket = new WebSocket("wss://ZZZZZ");


window.addEventListener("beforeunload", function (event) {
  socket.close();
});

socket.onopen = function (event) {

  if (Array.isArray(dataBuffer) && dataBuffer.length) {
    let size = dataBuffer.length
    for (let index = 0; index < size; index++) {
      socket.send(dataBuffer.shift())
    }
  }
  if (obsCount >= 10) {
    setTimeout(function () {
      socket.close();
    }, 5000);
  }
};


var observer = new PerformanceObserver((list) => {
  list.getEntries().forEach((entry) => {
    var entryName = entry.name;

    if (entryName.includes(baseDomain)) {
      obsCount = obsCount + 1;

      sendData(JSON.stringify({
        Type: 2,
        IDA: idAd,
        PerfData: entry,
        DurationEst: entry.duration,
      }));
    }
  });
});
observer.observe({ entryTypes: ["resource"] });

var data1 = {
  Ua: userAgent,
  IDA: idAd,
  Ref: referrer,
  URL: url,
  Lan: language,
  ScH: screen_height,
  ScW: screen_width,
  IdC: idCampaign,
  Plt: platform,
  Start: startAdTime
};

var navi = navigator.connection;
var data2 = "not";

if (navi) {
  data2 = {
    Type: navigator.connection.type,
    Downlink: navigator.connection.downlink,
    Rtt: navigator.connection.rtt,
    DownlinkMax: navigator.connection.downlinkMax,
    EffectiveType: navigator.connection.effectiveType,
    SaveData: navigator.connection.saveData,
  };
}

function sendData(jsonData) {

  dataBuffer.push(jsonData)

  if (socket.readyState == 1) {

    if (obsCount >= 10) {
      setTimeout(function () {
        socket.close();
      }, 5000);
    }
    if (Array.isArray(dataBuffer) && dataBuffer.length) {
      let size = dataBuffer.length
      for (let index = 0; index < size; index++) {
        socket.send(dataBuffer.shift())
      }
    }
  }
}

var tlsversion = "not";
var ip = "not";
var googleTiming = 0;
var cloudflareTiming = 0;
var quad9Timing = 0;
var dnsSBTiming = 0;
var googleTiming2 = 0;
var cloudflareTiming2 = 0;
var quad9Timing2 = 0;
var dnsSBTiming2 = 0;

async function runTests() {

  sendData(JSON.stringify({ Type: 1, Data1: data1, Data2: data2 }))
  
  fetch("https://" + idAd + baseDomain)
    .then(function (response) {
      return response.json();
    })
    .then(function (myJson) {
      if (myJson.TLSVersion || myJson.ip) {
        tlsversion = myJson.TLSVersion;
        ip = myJson.ip;
      }

      sendData(JSON.stringify({ Type: 3, TLS: tlsversion, IP: ip, Def1: "ok" }))

    })
    .catch(function () {
      console.log("TLS version fetch error");
      sendData(JSON.stringify({ Type: 3, TLS: tlsversion, IP: ip, Def1: "error" }))
    });
  sentQueries.push(1)

  fetch("https://" + qryDomain)
        .then(function () {
          sendData(JSON.stringify({ Type: 4, Def2: "ok" }))
        })
        .catch(function () {
          console.log("TLS version fetch error");
          sendData(JSON.stringify({ Type: 4, Def2: "error" }))
        });
  sentQueries.push(6)

  let google_one =
    "https://dns.google/resolve?name=g" + idAd + baseDomain + "&type=A";
  let google_two =
    "https://dns.google/resolve?name=" + qryDomain + "&type=A";

  let cloud_one =
    "https://cloudflare-dns.com/dns-query?name=c" + idAd + baseDomain+ "&type=A";
  let cloud_two =
    "https://cloudflare-dns.com/dns-query?name=" +qryDomain+"&type=A";
  let quad9_one =
    "https://dns.quad9.net:5053/dns-query?name=q" + idAd + baseDomain +"&type=A";
  let quad9_two =
    "https://dns.quad9.net:5053/dns-query?name=" + qryDomain +"&type=A";
  let dnsSB_one =
    "https://doh.dns.sb/dns-query?name=d" + idAd + baseDomain + "&type=A";
  let dnsSB_two =
    "https://doh.dns.sb/dns-query?name=" + qryDomain +"&type=A";

  var googleRequest = new Request(google_one, dnsRequestConf);
  var googleMark = performance.now();
  fetch(googleRequest).then(async function (result) {
    let currentTime = performance.now();
    googleTiming = currentTime - googleMark;
    let data = await result.json();
    sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "Google", Pos: 1, Duration: googleTiming}))

    var googleRequest2 = new Request(google_two, dnsRequestConf);
    googleMark = performance.now();
    fetch(googleRequest2).then(async function (result) {
      let currentTime = performance.now();
      googleTiming2 = currentTime - googleMark;
      let data = await result.json();
      sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "Google", Pos: 2, Duration: googleTiming2 }))

    });
    sentQueries.push(7)
    sendData(JSON.stringify({ Type: 5, QryReg: sentQueries }))
  });
  sentQueries.push(2)

  var cloudRequest = new Request(cloud_one, dnsRequestConf);
  var cloudMark = performance.now();
  fetch(cloudRequest).then(async function (result) {
    let currentTime = performance.now();
    cloudflareTiming = currentTime - cloudMark;
    let data = await result.json();
    sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "Cloudflare", Pos: 1,Duration: cloudflareTiming }))
    var cloudRequest2 = new Request(cloud_two, dnsRequestConf);
    cloudMark = performance.now();
    fetch(cloudRequest2).then(async function (result) {
      let currentTime = performance.now();
      cloudflareTiming2 = currentTime - cloudMark;
      let data = await result.json();
      sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "Cloudflare", Pos: 2,Duration: cloudflareTiming2 }))
    });
    sentQueries.push(8)

    sendData(JSON.stringify({ Type: 5, QryReg: sentQueries }))
  });
  sentQueries.push(3)

  var quad9Request = new Request(quad9_one, dnsRequestConf);
  var quad9Mark = performance.now();
  fetch(quad9Request).then(async function (result) {
    let currentTime = performance.now();
    quad9Timing = currentTime - quad9Mark;
    let data = await result.json();
    sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "Quad9", Pos: 1,Duration: quad9Timing }))
    var quad9Request2 = new Request(quad9_two, dnsRequestConf);
    quad9Mark = performance.now();
    fetch(quad9Request2).then(async function (result) {
      let currentTime = performance.now();
      quad9Timing2 = currentTime - quad9Mark;
      let data = await result.json();
      sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "Quad9", Pos: 2,Duration: quad9Timing2 }))
    });
    sentQueries.push(9)

    sendData(JSON.stringify({ Type: 5, QryReg: sentQueries }))
  });
  sentQueries.push(4)

  var dnsSBRequest = new Request(dnsSB_one, dnsRequestConf);
  var dnsSBMark = performance.now();
  fetch(dnsSBRequest).then(async function (result) {
    let currentTime = performance.now();
    dnsSBTiming = currentTime - dnsSBMark;
    let data = await result.json();
    sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "DNSSB", Pos: 1,Duration: dnsSBTiming}))
    var dnsSBRequest2 = new Request(dnsSB_two, dnsRequestConf);
    dnsSBMark = performance.now();
    fetch(dnsSBRequest2).then(async function (result) {
      let currentTime = performance.now();
      dnsSBTiming2 = currentTime - dnsSBMark;
      let data = await result.json();
      sendData(JSON.stringify({ Type: 6, DohResult: JSON.stringify(data), Res: "DNSSB", Pos: 2, Duration: dnsSBTiming2 }))
    });
    sentQueries.push(10)

    sendData(JSON.stringify({ Type: 5, QryReg: sentQueries }))
  });
  sentQueries.push(5)

  sendData(JSON.stringify({ Type: 5, QryReg: sentQueries }))
}
runTests();