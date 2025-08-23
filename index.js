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

// 播放器HTML页面
const playerHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>音乐播放器</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#3b82f6',
                        secondary: '#10b981',
                        dark: '#1e293b',
                        light: '#f8fafc'
                    },
                    fontFamily: {
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                    },
                }
            }
        }
    </script>
    <style type="text/tailwindcss">
        @layer utilities {
            .content-auto {
                content-visibility: auto;
            }
            .player-shadow {
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.12);
            }
            .progress-thumb {
                @apply appearance-none w-4 h-4 rounded-full bg-primary cursor-pointer shadow-md;
            }
            .progress-thumb::-webkit-slider-thumb {
                @apply appearance-none w-4 h-4 rounded-full bg-primary cursor-pointer shadow-md;
            }
        }
    </style>
</head>
<body class="bg-gradient-to-br from-gray-50 to-gray-100 min-h-screen flex flex-col items-center justify-center p-4 font-sans">
    <div class="w-full max-w-md bg-white rounded-2xl player-shadow overflow-hidden">
        <div class="p-6">
            <h1 class="text-[clamp(1.5rem,3vw,2rem)] font-bold text-center text-dark mb-6">音乐播放器</h1>
            
            <div class="mb-6">
                <label for="musicId" class="block text-sm font-medium text-gray-700 mb-2">音乐ID</label>
                <input type="text" id="musicId" placeholder="输入音乐ID" 
                       class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-primary transition-all"
                       value="\${musicId || ''}">
                
                <label for="quality" class="block text-sm font-medium text-gray-700 mt-4 mb-2">音质选择</label>
                <select id="quality" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-primary transition-all">
                    <option value="1">流畅 (64k acc)</option>
                    <option value="2">标准 (128k mp3)</option>
                    <option value="3" selected>高清 (160k mp3)</option>
                    <option value="4">无损 (320k mp3)</option>
                    <option value="5">母带 (2000k flac)</option>
                </select>
                
                <button id="loadMusic" class="w-full mt-4 bg-primary hover:bg-primary/90 text-white font-medium py-2 px-4 rounded-lg transition-all flex items-center justify-center">
                    <i class="fa fa-search mr-2"></i> 加载音乐
                </button>
            </div>
            
            <div id="loading" class="hidden text-center py-8">
                <div class="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
                <p class="mt-2 text-gray-600">加载中...</p>
            </div>
            
            <div id="error" class="hidden text-center py-8 text-red-500">
                <i class="fa fa-exclamation-triangle text-2xl mb-2"></i>
                <p id="errorMessage">加载失败，请重试</p>
            </div>
            
            <div id="playerContainer" class="hidden">
                <div class="bg-gray-100 rounded-xl p-4 mb-4">
                    <div class="relative pt-1">
                        <input type="range" id="progressBar" min="0" max="100" value="0" 
                               class="w-full h-2 bg-gray-300 rounded-lg appearance-none cursor-pointer accent-primary">
                    </div>
                    
                    <div class="flex justify-between text-sm text-gray-500 mt-1">
                        <span id="currentTime">00:00</span>
                        <span id="duration">00:00</span>
                    </div>
                </div>
                
                <div class="flex items-center justify-between mb-2">
                    <button id="skipBack" class="text-gray-600 hover:text-primary transition-colors">
                        <i class="fa fa-step-backward text-xl"></i>
                    </button>
                    
                    <button id="playPause" class="bg-primary hover:bg-primary/90 text-white rounded-full w-14 h-14 flex items-center justify-center transition-all">
                        <i class="fa fa-play text-xl"></i>
                    </button>
                    
                    <button id="skipForward" class="text-gray-600 hover:text-primary transition-colors">
                        <i class="fa fa-step-forward text-xl"></i>
                    </button>
                </div>
                
                <div class="mt-4">
                    <div class="flex items-center justify-between mb-1">
                        <i class="fa fa-volume-up text-gray-600"></i>
                        <span class="text-sm text-gray-500" id="volumeValue">100%</span>
                    </div>
                    <input type="range" id="volumeSlider" min="0" max="100" value="100" 
                           class="w-full h-2 bg-gray-300 rounded-lg appearance-none cursor-pointer accent-primary">
                </div>
                
                <div class="flex justify-center mt-4 space-x-4">
                    <button id="loop" class="text-gray-600 hover:text-primary transition-colors">
                        <i class="fa fa-repeat"></i>
                    </button>
                    <button id="mute" class="text-gray-600 hover:text-primary transition-colors">
                        <i class="fa fa-volume-off"></i>
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <audio id="audioPlayer" hidden></audio>
    
    <script>
        // 从URL获取参数
        const urlParams = new URLSearchParams(window.location.search);
        const musicId = urlParams.get('rid');
        const quality = urlParams.get('yz') || '3';
        
        // DOM元素
        const audioPlayer = document.getElementById('audioPlayer');
        const progressBar = document.getElementById('progressBar');
        const currentTimeEl = document.getElementById('currentTime');
        const durationEl = document.getElementById('duration');
        const playPauseBtn = document.getElementById('playPause');
        const volumeSlider = document.getElementById('volumeSlider');
        const volumeValue = document.getElementById('volumeValue');
        const muteBtn = document.getElementById('mute');
        const loopBtn = document.getElementById('loop');
        const skipBackBtn = document.getElementById('skipBack');
        const skipForwardBtn = document.getElementById('skipForward');
        const loadMusicBtn = document.getElementById('loadMusic');
        const musicIdInput = document.getElementById('musicId');
        const qualitySelect = document.getElementById('quality');
        const playerContainer = document.getElementById('playerContainer');
        const loadingIndicator = document.getElementById('loading');
        const errorIndicator = document.getElementById('error');
        const errorMessage = document.getElementById('errorMessage');
        
        // 设置初始值
        if (musicId) musicIdInput.value = musicId;
        if (quality) qualitySelect.value = quality;
        
        // 格式化时间（秒 -> mm:ss）
        function formatTime(seconds) {
            if (isNaN(seconds)) return '00:00';
            const mins = Math.floor(seconds / 60);
            const secs = Math.floor(seconds % 60);
            return \`\${mins.toString().padStart(2, '0')}:\${secs.toString().padStart(2, '0')}\`;
        }
        
        // 加载音乐
        async function loadMusic(id, yz) {
            if (!id) {
                showError('请输入音乐ID');
                return;
            }
            
            try {
                showLoading();
                hidePlayer();
                hideError();
                
                const response = await fetch(\`/api?rid=\${id}&yz=\${yz}\`);
                if (!response.ok) throw new Error('获取音乐地址失败');
                
                const musicUrl = await response.text();
                if (!musicUrl || musicUrl.includes('参数错误')) {
                    throw new Error('无效的音乐ID或获取地址失败');
                }
                
                // 设置音频源
                audioPlayer.src = musicUrl;
                await audioPlayer.load();
                
                // 显示播放器
                showPlayer();
                hideLoading();
                
                // 自动播放（受浏览器政策限制）
                try {
                    await audioPlayer.play();
                    updatePlayPauseIcon();
                } catch (e) {
                    console.log('自动播放失败，需要用户交互');
                }
                
            } catch (error) {
                console.error('加载音乐错误:', error);
                showError(error.message);
                hideLoading();
            }
        }
        
        // 事件监听
        loadMusicBtn.addEventListener('click', () => {
            loadMusic(musicIdInput.value, qualitySelect.value);
        });
        
        // 播放/暂停
        playPauseBtn.addEventListener('click', () => {
            if (audioPlayer.paused) {
                audioPlayer.play();
            } else {
                audioPlayer.pause();
            }
            updatePlayPauseIcon();
        });
        
        // 更新播放/暂停图标
        function updatePlayPauseIcon() {
            const icon = playPauseBtn.querySelector('i');
            if (audioPlayer.paused) {
                icon.className = 'fa fa-play text-xl';
            } else {
                icon.className = 'fa fa-pause text-xl';
            }
        }
        
        // 进度更新
        audioPlayer.addEventListener('timeupdate', () => {
            const progress = (audioPlayer.currentTime / audioPlayer.duration) * 100;
            progressBar.value = progress || 0;
            currentTimeEl.textContent = formatTime(audioPlayer.currentTime);
        });
        
        // 音频元数据加载完成
        audioPlayer.addEventListener('loadedmetadata', () => {
            durationEl.textContent = formatTime(audioPlayer.duration);
        });
        
        // 进度条拖动
        progressBar.addEventListener('input', () => {
            const seekTime = (progressBar.value / 100) * audioPlayer.duration;
            audioPlayer.currentTime = seekTime;
        });
        
        // 音量控制
        volumeSlider.addEventListener('input', () => {
            audioPlayer.volume = volumeSlider.value / 100;
            volumeValue.textContent = \`\${volumeSlider.value}%\`;
            updateMuteIcon();
        });
        
        // 静音切换
        muteBtn.addEventListener('click', () => {
            audioPlayer.muted = !audioPlayer.muted;
            updateMuteIcon();
        });
        
        // 更新静音图标
        function updateMuteIcon() {
            const icon = muteBtn.querySelector('i');
            if (audioPlayer.muted || audioPlayer.volume === 0) {
                icon.className = 'fa fa-volume-off';
            } else if (audioPlayer.volume < 0.5) {
                icon.className = 'fa fa-volume-down';
            } else {
                icon.className = 'fa fa-volume-up';
            }
        }
        
        // 循环播放
        loopBtn.addEventListener('click', () => {
            audioPlayer.loop = !audioPlayer.loop;
            loopBtn.classList.toggle('text-primary', audioPlayer.loop);
        });
        
        // 快退10秒
        skipBackBtn.addEventListener('click', () => {
            audioPlayer.currentTime = Math.max(0, audioPlayer.currentTime - 10);
        });
        
        // 快进10秒
        skipForwardBtn.addEventListener('click', () => {
            audioPlayer.currentTime = Math.min(audioPlayer.duration, audioPlayer.currentTime + 10);
        });
        
        // 播放结束
        audioPlayer.addEventListener('ended', () => {
            updatePlayPauseIcon();
        });
        
        // 错误处理
        audioPlayer.addEventListener('error', (e) => {
            console.error('音频错误:', e);
            showError('播放失败，请尝试其他音乐或音质');
        });
        
        // UI控制函数
        function showPlayer() {
            playerContainer.classList.remove('hidden');
        }
        
        function hidePlayer() {
            playerContainer.classList.add('hidden');
        }
        
        function showLoading() {
            loadingIndicator.classList.remove('hidden');
        }
        
        function hideLoading() {
            loadingIndicator.classList.add('hidden');
        }
        
        function showError(message) {
            errorMessage.textContent = message;
            errorIndicator.classList.remove('hidden');
        }
        
        function hideError() {
            errorIndicator.classList.add('hidden');
        }
        
        // 如果URL有参数，自动加载
        if (musicId) {
            loadMusic(musicId, quality);
        }
    </script>
</body>
</html>
`;

// 路由
app.get('/', (req, res) => {
    // 从URL参数获取音乐ID
    const musicId = req.query.rid || '';
    // 将音乐ID注入到HTML中
    const html = playerHtml.replace('${musicId || \'\'}', musicId);
    res.send(html);
});

app.get('/api', async (req, res) => {
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
        
        // 发送请求获取实际播放地址，使用手机UA
        const response = await fetch(musicUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-G9980) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
            }
        });
        
        if (!response.ok) {
            throw new Error(`请求失败: ${response.status}`);
        }
        
        const responseText = await response.text();
        
        // 提取URL
        const match = responseText.match(/url=(.*?)\s/);
        if (!match || !match[1]) {
            throw new Error('无法提取音乐URL');
        }
        
        res.send(match[1]);
    } catch (error) {
        console.error('API错误:', error);
        res.status(500).send(`服务器错误: ${error.message}`);
    }
});

// 启动服务器
app.listen(port, () => {
    console.log(`服务器运行在端口 ${port}`);
});
    
