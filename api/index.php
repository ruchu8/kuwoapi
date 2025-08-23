<?php
// 示例：处理请求并返回响应
header("Content-Type: text/html; charset=utf-8");

echo "<h1>PHP 7 部署在 Vercel 成功！</h1>";
echo "PHP 版本: " . phpversion() . "<br>";

// 处理路由逻辑（根据需要扩展）
$path = $_SERVER['REQUEST_URI'];
echo "当前路径: " . $path;
