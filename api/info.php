<?php
header("Content-Type: text/html; charset=utf-8");
?>
<!DOCTYPE html>
<html>
<head>
    <title>Vercel PHP 测试</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .info-box { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .success { color: #28a745; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Vercel PHP 部署测试</h1>
    <div class="info-box">
        <p class="success">部署成功！</p>
        <p>PHP 版本: <?php echo phpversion(); ?></p>
        <p>服务器时间: <?php echo date('Y-m-d H:i:s'); ?></p>
        <p>服务器软件: <?php echo $_SERVER['SERVER_SOFTWARE'] ?? '未知'; ?></p>
    </div>
</body>
</html>
