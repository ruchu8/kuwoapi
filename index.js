const express = require('express');
const axios = require('axios');
const app = express();
const port = process.env.PORT || 3000;

// 配置视图引擎和静态文件
app.use(express.static('public'));
app.set('view engine', 'ejs');

// 原PHP代码中的加密相关常量和函数转换为JavaScript
const hexs = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
const DES_MODE_DECRYPT = 1;
const arrayE = [31, 0, DES_MODE_DECRYPT, 2, 3, 4, -1, -1, 3, 4, 5, 6, 7, 8, -1, -1, 7, 8, 9, 10, 11, 12, -1, -1, 11, 12, 13, 14, 15, 16, -1, -1, 15, 16, 17, 18, 19, 20, -1, -1, 19, 20, 21, 22, 23, 24, -1, -1, 23, 24, 25, 26, 27, 28, -1, -1, 27, 28, 29, 30, 31, 30, -1, -1];
const arrayIP = [57, 49, 41, 33, 25, 17, 9, DES_MODE_DECRYPT, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6];
const arrayIP_1 = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, DES_MODE_DECRYPT, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24];
const arrayLs = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const arrayLsMask = [0, 0x100001, 0x300003];
const arrayMask = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648, 4294967296, 8589934592, 17179869184, 34359738368, 68719476736, 137438953472, 274877906944, 549755813888, 1099511627776, 2199023255552, 4398046511104, 8796093022208, 17592186044416, 35184372088832, 70368744177664, 140737488355328, 281474976710656, 562949953421312, 1125899906842624, 2251799813685248, 4503599627370496, 9007199254740992, 18014398509481984, 36028797018963968, 72057594037927936, 144115188075855872, 288230376151711744, 576460752303423488, 1152921504606846976, 2305843009213693952, 4611686018427387904, -9223372036854775808n];
const arrayP = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24];
const arrayPC_1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3];
const arrayPC_2 = [13, 16, 10, 23, 0, 4, -1, -1, 2, 27, 14, 5, 20, 9, -1, -1, 22, 18, 11, 3, 25, 7, -1, -1, 15, 6, 26, 19, 12, 1, -1, -1, 40, 51, 30, 36, 46, 54, -1, -1, 29, 39, 50, 44, 32, 47, -1, -1, 43, 48, 38, 55, 33, 52, -1, -1, 45, 41, 49, 35, 28, 31, -1, -1];
const matrixNSBox = [[14, 4, 3, 15, 2, 13, 5, 3, 13, 14, 6, 9, 11, 2, 0, 5, 4, 1, 10, 12, 15, 6, 9, 10, 1, 8, 12, 7, 8, 11, 7, 0, 0, 15, 10, 5, 14, 4, 9, 10, 7, 8, 12, 3, 13, 1, 3, 6, 15, 12, 6, 11, 2, 9, 5, 0, 4, 2, 11, 14, 1, 7, 8, 13], [15, 0, 9, 5, 6, 10, 12, 9, 8, 7, 2, 12, 3, 13, 5, 2, 1, 14, 7, 8, 11, 4, 0, 3, 14, 11, 13, 6, 4, 1, 10, 15, 3, 13, 12, 11, 15, 3, 6, 0, 4, 10, 1, 7, 8, 4, 11, 14, 13, 8, 0, 6, 2, 15, 9, 5, 7, 1, 10, 12, 14, 2, 5, 9], [10, 13, 1, 11, 6, 8, 11, 5, 9, 4, 12, 2, 15, 3, 2, 14, 0, 6, 13, 1, 3, 15, 4, 10, 14, 9, 7, 12, 5, 0, 8, 7, 13, 1, 2, 4, 3, 6, 12, 11, 0, 13, 5, 14, 6, 8, 15, 2, 7, 10, 8, 15, 4, 9, 11, 5, 9, 0, 14, 3, 10, 7, 1, 12], [7, 10, 1, 15, 0, 12, 11, 5, 14, 9, 8, 3, 9, 7, 4, 8, 13, 6, 2, 1, 6, 11, 12, 2, 3, 0, 5, 14, 10, 13, 15, 4, 13, 3, 4, 9, 6, 10, 1, 12, 11, 0, 2, 5, 0, 13, 14, 2, 8, 15, 7, 4, 15, 1, 10, 7, 5, 6, 12, 11, 3, 8, 9, 14], [2, 4, 8, 15, 7, 10, 13, 6, 4, 1, 3, 12, 11, 7, 14, 0, 12, 2, 5, 9, 10, 13, 0, 3, 1, 11, 15, 5, 6, 8, 9, 14, 14, 11, 5, 6, 4, 1, 3, 10, 2, 12, 15, 0, 13, 2, 8, 5, 11, 8, 0, 15, 7, 14, 9, 4, 12, 7, 10, 9, 1, 13, 6, 3], [12, 9, 0, 7, 9, 2, 14, 1, 10, 15, 3, 4, 6, 12, 5, 11, 1, 14, 13, 0, 2, 8, 7, 13, 15, 5, 4, 10, 8, 3, 11, 6, 10, 4, 6, 11, 7, 9, 0, 6, 4, 2, 13, 1, 9, 15, 3, 8, 15, 3, 1, 14, 12, 5, 11, 0, 2, 12, 14, 7, 5, 10, 8, 13], [4, 1, 3, 10, 15, 12, 5, 0, 2, 11, 9, 6, 8, 7, 6, 9, 11, 4, 12, 15, 0, 3, 10, 5, 14, 13, 7, 8, 13, 14, 1, 2, 13, 6, 14, 9, 4, 1, 2, 14, 11, 13, 5, 0, 1, 10, 8, 3, 0, 11, 3, 5, 9, 4, 15, 2, 7, 8, 12, 15, 10, 7, 6, 12], [13, 7, 10, 0, 6, 9, 5, 15, 8, 4, 3, 10, 11, 14, 12, 5, 2, 11, 9, 6, 15, 12, 0, 3, 4, 1, 14, 13, 1, 2, 7, 8, 1, 2, 12, 15, 10, 4, 0, 3, 13, 14, 6, 9, 7, 8, 9, 6, 15, 1, 5, 12, 3, 10, 14, 5, 8, 7, 11, 0, 4, 13, 2, 11]];
const SECRET_KEY = "ylzsxkwm";

// 辅助函数：将PHP的ord函数转换为JavaScript
function ord(str) {
    return str.charCodeAt(0);
}

// 位转换函数
function bit_transform(arr_int, n, l) {
    let l2 = 0;
    for (let i = 0; i < n; i++) {
        if (arr_int[i] < 0 || (l & BigInt(arrayMask[arr_int[i]])) === 0n) {
            continue;
        }
        l2 |= BigInt(arrayMask[i]);
    }
    return l2;
}

// DES64函数
function DES64(longs, l) {
    let out = 0n;
    let SOut = 0n;
    const pR = [0, 0, 0, 0, 0, 0, 0, 0];
    let pSource = [0n, 0n];
    let sbi = 0;
    let L = 0n;
    let R = 0n;

    out = bit_transform(arrayIP, 64, BigInt(l));

    pSource[0] = out & 0xFFFFFFFFn;
    pSource[1] = (out & (-4294967296n)) >> 32n;

    for (let i = 0; i < 16; i++) {
        R = pSource[1];
        R = bit_transform(arrayE, 64, R);
        R ^= BigInt(longs[i]);

        for (let j = 0; j < 8; j++) {
            pR[j] = Number(R >> BigInt(j * 8) & 0xFFn);
        }

        SOut = 0n;
        for (sbi = 7; sbi >= 0; sbi--) {
            SOut <<= 4n;
            SOut |= BigInt(matrixNSBox[sbi][pR[sbi]]);
        }

        R = bit_transform(arrayP, 32, SOut);
        L = pSource[0];

        pSource[0] = pSource[1];
        pSource[1] = L ^ R;
    }

    pSource = [...pSource].reverse();

    out = (pSource[1] << 32n) | pSource[0];
    out = bit_transform(arrayIP_1, 64, out);

    return out;
}

// 子密钥生成函数
function sub_keys(l, longs, n) {
    let l2 = bit_transform(arrayPC_1, 56, BigInt(l));

    for (let i = 0; i < 16; i++) {
        const shift = arrayLs[i];
        const mask = BigInt(arrayLsMask[shift]);
        l2 = ((l2 & mask) << BigInt(28 - shift)) | ((l2 & ~mask) >> BigInt(shift));
        longs[i] = Number(bit_transform(arrayPC_2, 64, l2));
    }

    let j = 0;
    while (n === 1 && j < 8) {
        const l3 = longs[j];
        longs[j] = longs[15 - j];
        longs[15 - j] = l3;
        j += 1;
    }
}

// 加密函数
function encrypt(msg) {
    const key = SECRET_KEY;
    
    let l = 0;
    for (let i = 0; i < 8; i++) {
        l |= ord(key[i]) << (i * 8);
    }

    const j = Math.floor(msg.length / 8);
    const arrLong1 = new Array(16).fill(0);
    sub_keys(l, arrLong1, 0);

    const arrLong2 = new Array(j).fill(0);
    for (let m = 0; m < j; m++) {
        for (let n = 0; n < 8; n++) {
            const charCode = ord(msg[n + m * 8] || '\0');
            arrLong2[m] |= charCode << (n * 8);
        }
    }

    const arrLong3 = new Array(Math.floor((1 + 8 * (j + 1)) / 8)).fill(0);
    for (let i1 = 0; i1 < j; i1++) {
        arrLong3[i1] = DES64(arrLong1, arrLong2[i1]);
    }

    const arrByte1 = msg.substring(j * 8);
    let l2 = 0;
    for (let i1 = 0; i1 < msg.length % 8; i1++) {
        l2 |= ord(arrByte1[i1]) << (i1 * 8);
    }
    arrLong3[j] = DES64(arrLong1, l2);

    let arrByte2 = '';
    let i4 = 0;
    for (const l3 of arrLong3) {
        for (let i6 = 0; i6 < 8; i6++) {
            const charCode = Number(l3 >> BigInt(i6 * 8) & 0xFFn);
            arrByte2 += String.fromCharCode(charCode);
            i4 += 1;
        }
    }

    return arrByte2;
}

// Base64加密函数
function base64_encrypt(msg) {
    const b1 = encrypt(msg);
    const buffer = Buffer.from(b1, 'binary');
    return buffer.toString('base64').replace(/[\r\n]/g, '');
}

// 获取音乐URL
function getMusicUrlUrl(id, format, br) {
    const willEnc = `user=0&android_id=0&prod=kwplayer_ar_8.5.5.0&corp=kuwo&newver=3&vipver=8.5.5.0&source=kwplayer_ar_8.5.5.0_apk_keluze.apk&p2p=1&notrace=0&type=convert_url2&br=${br}&format=${format}&sig=0&rid=${id}&priority=bitrate&loginUid=0&network=WIFI&loginSid=0&mode=download`;
    const encrypted = base64_encrypt(willEnc);
    return `http://mobi.kuwo.cn/mobi.s?f=kuwo&q=${encodeURIComponent(encrypted)}`;
}

// 路由：首页，显示播放器
app.get('/', (req, res) => {
    res.render('index', { musicUrl: null, rid: req.query.rid || '', yz: req.query.yz || '3' });
});

// 路由：获取音乐URL的API
app.get('/api/get-music-url', async (req, res) => {
    try {
        const { rid, yz = '3' } = req.query;
        
        if (!rid) {
            return res.status(400).json({ error: '参数错误：缺少rid' });
        }
        
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
        
        const musicUrl = getMusicUrlUrl(rid, format, br);
        
        // 发送请求获取真实音乐地址，使用手机UA
        const response = await axios.get(musicUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-G9980) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
            },
            timeout: 10000
        });
        
        // 从响应中提取音乐URL
        const match = response.data.match(/url=(.*?)\s/);
        if (match && match[1]) {
            return res.json({ url: match[1] });
        } else {
            return res.status(404).json({ error: '未找到音乐URL' });
        }
    } catch (error) {
        console.error('获取音乐URL失败:', error);
        res.status(500).json({ error: '获取音乐URL失败' });
    }
});

// 启动服务器
app.listen(port, () => {
    console.log(`服务器运行在 http://localhost:${port}`);
});
