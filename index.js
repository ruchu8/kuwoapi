const express = require('express');
const fetch = require('node-fetch');
const app = express();
const port = process.env.PORT || 3000;

// 处理跨域
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// 国内代理服务器配置（这里需要您提供可用的国内代理）
// 可以使用如快代理、阿布云等国内代理服务
const PROXY_CONFIG = {
  host: process.env.PROXY_HOST || 'your-proxy-host',
  port: process.env.PROXY_PORT || 'your-proxy-port',
  auth: process.env.PROXY_AUTH || 'username:password' // 代理认证信息
};

// DES加密相关函数
const SECRET_KEY = "ylzsxkwm";
const arrayMask = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496, 9007199254740992, 18014398509481984, 36028797018963968, 72057594037927936, 144115188075855872, 288230376151711744, 576460752303423488, 1152921504606846976, 2305843009213693952, 4611686018427387904, -9223372036854775808];
const DES_MODE_DECRYPT = 1;
const arrayE = [31, 0, DES_MODE_DECRYPT, 2, 3, 4, -1, -1, 3, 4, 5, 6, 7, 8, -1, -1, 7, 8, 9, 10, 11, 12, -1, -1, 11, 12, 13, 14, 15, 16, -1, -1, 15, 16, 17, 18, 19, 20, -1, -1, 19, 20, 21, 22, 23, 24, -1, -1, 23, 24, 25, 26, 27, 28, -1, -1, 27, 28, 29, 30, 31, 30, -1, -1];
const arrayIP = [57, 49, 41, 33, 25, 17, 9, DES_MODE_DECRYPT, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6];
const arrayIP_1 = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, DES_MODE_DECRYPT, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24];
const arrayLs = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const arrayLsMask = [0, 0x100001, 0x300003];
const arrayP = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24];
const arrayPC_1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3];
const arrayPC_2 = [13, 16, 10, 23, 0, 4, -1, -1, 2, 27, 14, 5, 20, 9, -1, -1, 22, 18, 11, 3, 25, 7, -1, -1, 15, 6, 26, 19, 12, 1, -1, -1, 40, 51, 30, 36, 46, 54, -1, -1, 29, 39, 50, 44, 32, 47, -1, -1, 43, 48, 38, 55, 33, 52, -1, -1, 45, 41, 49, 35, 28, 31, -1, -1];
const matrixNSBox = [[14, 4, 3, 15, 2, 13, 5, 3, 13, 14, 6, 9, 11, 2, 0, 5, 4, 1, 10, 12, 15, 6, 9, 10, 1, 8, 12, 7, 8, 11, 7, 0, 0, 15, 10, 5, 14, 4, 9, 10, 7, 8, 12, 3, 13, 1, 3, 6, 15, 12, 6, 11, 2, 9, 5, 0, 4, 2, 11, 14, 1, 7, 8, 13], [15, 0, 9, 5, 6, 10, 12, 9, 8, 7, 2, 12, 3, 13, 5, 2, 1, 14, 7, 8, 11, 4, 0, 3, 14, 11, 13, 6, 4, 1, 10, 15, 3, 13, 12, 11, 15, 3, 6, 0, 4, 10, 1, 7, 8, 4, 11, 14, 13, 8, 0, 6, 2, 15, 9, 5, 7, 1, 10, 12, 14, 2, 5, 9], [10, 13, 1, 11, 6, 8, 11, 5, 9, 4, 12, 2, 15, 3, 2, 14, 0, 6, 13, 1, 3, 15, 4, 10, 14, 9, 7, 12, 5, 0, 8, 7, 13, 1, 2, 4, 3, 6, 12, 11, 0, 13, 5, 14, 6, 8, 15, 2, 7, 10, 8, 15, 4, 9, 11, 5, 9, 0, 14, 3, 10, 7, 1, 12], [7, 10, 1, 15, 0, 12, 11, 5, 14, 9, 8, 3, 9, 7, 4, 8, 13, 6, 2, 1, 6, 11, 12, 2, 3, 0, 5, 14, 10, 13, 15, 4, 13, 3, 4, 9, 6, 10, 1, 12, 11, 0, 2, 5, 0, 13, 14, 2, 8, 15, 7, 4, 15, 1, 10, 7, 5, 6, 12, 11, 3, 8, 9, 14], [2, 4, 8, 15, 7, 10, 13, 6, 4, 1, 3, 12, 11, 7, 14, 0, 12, 2, 5, 9, 10, 13, 0, 3, 1, 11, 15, 5, 6, 8, 9, 14, 14, 11, 5, 6, 4, 1, 3, 10, 2, 12, 15, 0, 13, 2, 8, 5, 11, 8, 0, 15, 7, 14, 9, 4, 12, 7, 10, 9, 1, 13, 6, 3], [12, 9, 0, 7, 9, 2, 14, 1, 10, 15, 3, 4, 6, 12, 5, 11, 1, 14, 13, 0, 2, 8, 7, 13, 15, 5, 4, 10, 8, 3, 11, 6, 10, 4, 6, 11, 7, 9, 0, 6, 4, 2, 13, 1, 9, 15, 3, 8, 15, 3, 1, 14, 12, 5, 11, 0, 2, 12, 14, 7, 5, 10, 8, 13], [4, 1, 3, 10, 15, 12, 5, 0, 2, 11, 9, 6, 8, 7, 6, 9, 11, 4, 12, 15, 0, 3, 10, 5, 14, 13, 7, 8, 13, 14, 1, 2, 13, 6, 14, 9, 4, 1, 2, 14, 11, 13, 5, 0, 1, 10, 8, 3, 0, 11, 3, 5, 9, 4, 15, 2, 7, 8, 12, 15, 10, 7, 6, 12], [13, 7, 10, 0, 6, 9, 5, 15, 8, 4, 3, 10, 11, 14, 12, 5, 2, 11, 9, 6, 15, 12, 0, 3, 4, 1, 14, 13, 1, 2, 7, 8, 1, 2, 12, 15, 10, 4, 0, 3, 13, 14, 6, 9, 7, 8, 9, 6, 15, 1, 5, 12, 3, 10, 14, 5, 8, 7, 11, 0, 4, 13, 2, 11]];

function bit_transform(arr_int, n, l) {
    let l2 = 0;
    for (let i = 0; i < n; i++) {
        if (arr_int[i] < 0 || (l & arrayMask[arr_int[i]]) === 0) {
            continue;
        }
        l2 |= arrayMask[i];
    }
    return l2;
}

function DES64(longs, l) {
    let out = 0;
    let SOut = 0;
    const pR = [0, 0, 0, 0, 0, 0, 0, 0];
    const pSource = [0, 0];
    let L = 0;
    let R = 0;

    out = bit_transform(arrayIP, 64, l);

    pSource[0] = 0xFFFFFFFF & out;
    pSource[1] = (-4294967296 & out) >> 32;

    for (let i = 0; i < 16; i++) {
        R = pSource[1];
        R = bit_transform(arrayE, 64, R);
        R ^= longs[i];

        for (let j = 0; j < 8; j++) {
            pR[j] = 255 & (R >> (j * 8));
        }

        SOut = 0;
        for (let sbi = 7; sbi >= 0; sbi--) {
            SOut <<= 4;
            SOut |= matrixNSBox[sbi][pR[sbi]];
        }

        R = bit_transform(arrayP, 32, SOut);
        L = pSource[0];

        pSource[0] = pSource[1];
        pSource[1] = L ^ R;
    }

    pSource.reverse();

    out = (-4294967296 & (pSource[1] << 32)) | (0xFFFFFFFF & pSource[0]);
    out = bit_transform(arrayIP_1, 64, out);

    return out;
}

function sub_keys(l, longs, n) {
    let l2 = bit_transform(arrayPC_1, 56, l);

    for (let i = 0; i < 16; i++) {
        l2 = ((l2 & arrayLsMask[arrayLs[i]]) << (28 - arrayLs[i]) | (l2 & ~arrayLsMask[arrayLs[i]]) >> arrayLs[i]);
        longs[i] = bit_transform(arrayPC_2, 64, l2);
    }

    let j = 0;
    while (n === 1 && j < 8) {
        const l3 = longs[j];
        longs[j] = longs[15 - j];
        longs[15 - j] = l3;
        j += 1;
    }
}

function encrypt(msg) {
    const key = SECRET_KEY;
    let l = 0;
    for (let i = 0; i < 8; i++) {
        l |= key.charCodeAt(i) << (i * 8);
    }

    const j = Math.floor(msg.length / 8);
    const arrLong1 = new Array(16).fill(0);
    sub_keys(l, arrLong1, 0);

    const arrLong2 = new Array(j).fill(0);
    for (let m = 0; m < j; m++) {
        for (let n = 0; n < 8; n++) {
            arrLong2[m] |= msg.charCodeAt(n + m * 8) << (n * 8);
        }
    }

    const arrLong3 = new Array(Math.floor((1 + 8 * (j + 1)) / 8)).fill(0);
    for (let i1 = 0; i1 < j; i1++) {
        arrLong3[i1] = DES64(arrLong1, arrLong2[i1]);
    }

    const arrByte1 = msg.substring(j * 8);
    let l2 = 0;
    for (let i1 = 0; i1 < msg.length % 8; i1++) {
        l2 |= arrByte1.charCodeAt(i1) << (i1 * 8);
    }
    arrLong3[j] = DES64(arrLong1, l2);

    let arrByte2 = '';
    let i4 = 0;
    for (const l3 of arrLong3) {
        for (let i6 = 0; i6 < 8; i6++) {
            arrByte2 += String.fromCharCode(255 & (l3 >> (i6 * 8)));
            i4 += 1;
        }
    }

    return arrByte2;
}

function base64_encrypt(msg) {
    const b1 = encrypt(msg);
    return Buffer.from(b1).toString('base64').replace(/[\r\n]/g, '');
}

function getMusicUrlUrl(id, format, br) {
    const willEnc = `user=0&android_id=0&prod=kwplayer_ar_8.5.5.0&corp=kuwo&newver=3&vipver=8.5.5.0&source=kwplayer_ar_8.5.5.0_apk_keluze.apk&p2p=1&notrace=0&type=convert_url2&br=${br}&format=${format}&sig=0&rid=${id}&priority=bitrate&loginUid=0&network=WIFI&loginSid=0&mode=download`;
    return `http://mobi.kuwo.cn/mobi.s?f=kuwo&q=${base64_encrypt(willEnc)}`;
}

// 创建带代理的fetch函数
async function fetchWithProxy(url, options = {}) {
    // 如果未配置代理，直接请求
    if (!PROXY_CONFIG.host || !PROXY_CONFIG.port) {
        console.warn('未配置代理，可能导致访问失败');
        return fetch(url, options);
    }

    // 构建代理URL
    const proxyUrl = `http://${PROXY_CONFIG.auth ? `${PROXY_CONFIG.auth}@` : ''}${PROXY_CONFIG.host}:${PROXY_CONFIG.port}`;
    
    // 设置代理请求头
    const proxyOptions = {
        ...options,
        agent: new (require('https-proxy-agent'))(proxyUrl),
        headers: {
            ...options.headers,
            'X-Forwarded-For': '114.114.114.114', // 模拟国内IP
            'X-Real-IP': '114.114.114.114'
        },
        timeout: 10000
    };

    return fetch(url, proxyOptions);
}

// 简单的前端页面
const frontendHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MP3地址获取工具</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white rounded-xl shadow-lg p-6">
        <h1 class="text-2xl font-bold text-center mb-6 text-gray-800">MP3地址获取</h1>
        
        <div class="mb-4">
            <label for="rid" class="block text-sm font-medium text-gray-700 mb-1">音乐ID (rid)</label>
            <input type="text" id="rid" placeholder="请输入音乐ID" 
                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all">
        </div>
        
        <div class="mb-6">
            <label for="quality" class="block text-sm font-medium text-gray-700 mb-1">音质选择</label>
            <select id="quality" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all">
                <option value="3" selected>标准MP3 (160k)</option>
                <option value="4">高清MP3 (320k)</option>
                <option value="5">无损FLAC (2000k)</option>
                <option value="2">普通MP3 (128k)</option>
                <option value="1">流畅ACC (64k)</option>
            </select>
        </div>
        
        <button id="fetchBtn" class="w-full bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded-lg transition-all flex items-center justify-center">
            <i class="fa fa-search mr-2"></i> 获取MP3地址
        </button>
        
        <div id="loading" class="hidden mt-4 text-center">
            <div class="inline-block animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-blue-500"></div>
            <p class="mt-2 text-gray-600 text-sm">获取中...</p>
        </div>
        
        <div id="result" class="mt-4 hidden">
            <label class="block text-sm font-medium text-gray-700 mb-1">MP3地址:</label>
            <div class="flex">
                <input type="text" id="mp3Url" readonly 
                       class="flex-1 px-4 py-2 border border-gray-300 rounded-l-lg bg-gray-50">
                <button id="copyBtn" class="bg-gray-200 hover:bg-gray-300 px-4 py-2 rounded-r-lg transition-all">
                    <i class="fa fa-copy"></i>
                </button>
            </div>
            <div class="mt-4">
                <audio id="audioPlayer" controls class="w-full">
                    您的浏览器不支持音频播放
                </audio>
            </div>
        </div>
        
        <div id="error" class="mt-4 hidden p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm">
            <i class="fa fa-exclamation-circle mr-1"></i>
            <span id="errorMsg"></span>
        </div>
    </div>

    <script>
        document.getElementById('fetchBtn').addEventListener('click', async () => {
            const rid = document.getElementById('rid').value.trim();
            const quality = document.getElementById('quality').value;
            
            if (!rid) {
                showError('请输入音乐ID');
                return;
            }
            
            showLoading();
            hideResult();
            hideError();
            
            try {
                const response = await fetch(\`/getMp3?rid=\${encodeURIComponent(rid)}&yz=\${quality}\`);
                const mp3Url = await response.text();
                
                if (response.ok && mp3Url && !mp3Url.includes('错误')) {
                    showResult(mp3Url);
                } else {
                    showError(mp3Url || '获取失败，请重试');
                }
            } catch (err) {
                showError('网络错误，请稍后重试');
                console.error(err);
            } finally {
                hideLoading();
            }
        });
        
        document.getElementById('copyBtn').addEventListener('click', () => {
            const urlInput = document.getElementById('mp3Url');
            urlInput.select();
            document.execCommand('copy');
            
            const copyBtn = document.getElementById('copyBtn');
            const originalText = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="fa fa-check"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = originalText;
            }, 2000);
        });
        
        function showLoading() {
            document.getElementById('loading').classList.remove('hidden');
        }
        
        function hideLoading() {
            document.getElementById('loading').classList.add('hidden');
        }
        
        function showResult(url) {
            document.getElementById('mp3Url').value = url;
            document.getElementById('audioPlayer').src = url;
            document.getElementById('result').classList.remove('hidden');
        }
        
        function hideResult() {
            document.getElementById('result').classList.add('hidden');
        }
        
        function showError(message) {
            document.getElementById('errorMsg').textContent = message;
            document.getElementById('error').classList.remove('hidden');
        }
        
        function hideError() {
            document.getElementById('error').classList.add('hidden');
        }
    </script>
</body>
</html>
`;

// 路由
app.get('/', (req, res) => {
    res.send(frontendHtml);
});

app.get('/getMp3', async (req, res) => {
    try {
        const id = req.query.rid;
        const yz = req.query.yz || '3';
        
        if (!id) {
            return res.status(400).send('参数错误：缺少音乐ID');
        }
        
        // 确定格式和音质
        let format, br;
        if (yz === '1') {
            format = 'acc';
            br = '64kacc';
        } else if (yz === '2') {
            format = 'mp3';
            br = '128kmp3';
        } else if (yz === '3') {
            format = 'mp3';
            br = '160kmp3';
        } else if (yz === '4') {
            format = 'mp3';
            br = '320kmp3';
        } else if (yz === '5') {
            format = 'flac';
            br = '2000flac';
        } else {
            format = 'mp3';
            br = '160kmp3';
        }
        
        // 获取音乐URL
        const musicUrl = getMusicUrlUrl(id, format, br);
        console.log('请求的音乐接口地址:', musicUrl);
        
        // 使用国内代理发送请求，解决海外IP限制
        const response = await fetchWithProxy(musicUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-G9980) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
                'Referer': 'http://mobi.kuwo.cn/',
                'Accept': '*/*',
                'Connection': 'keep-alive'
            }
        });
        
        if (!response.ok) {
            console.error(`接口请求失败: ${response.status} ${response.statusText}`);
            throw new Error(`接口返回状态码: ${response.status}`);
        }
        
        const responseText = await response.text();
        console.log('接口返回内容:', responseText.substring(0, 200)); // 只打印前200字符
        
        // 提取URL的多种尝试
        let urlMatch;
        // 尝试多种正则模式
        const patterns = [
            /url=(.*?)\s/,
            /url=(.*?)&/,
            /url=(.*?)"/,
            /url=(.*?)$/
        ];
        
        for (const pattern of patterns) {
            urlMatch = responseText.match(pattern);
            if (urlMatch && urlMatch[1]) break;
        }
        
        if (!urlMatch || !urlMatch[1]) {
            throw new Error('无法从接口响应中提取MP3地址');
        }
        
        const mp3Url = urlMatch[1];
        console.log('提取到的MP3地址:', mp3Url);
        
        res.send(mp3Url);
    } catch (error) {
        console.error('获取MP3地址错误:', error);
        res.status(500).send(`获取失败: ${error.message}`);
    }
});

app.listen(port, () => {
    console.log(`服务器运行在端口 ${port}`);
});
