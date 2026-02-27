# 框架路由定位参考（v1）

## ThinkPHP
- 常见路由配置：route/*.php、route.php、config/route.php
- 控制器入口：app/*/controller/* 或 application/*/controller/*

## Laravel
- routes/web.php、routes/api.php、routes/*.php
- 关注 Route::get/post/any/resource 与中间件

## Symfony
- config/routes.yaml、config/routes/*.yaml
- 控制器中注解/属性路由（例如 #[Route]）

## Yii
- config/web.php 或 config/main.php 中 urlManager 规则
- controller/action 命名约定

## CodeIgniter
- CI4: app/Config/Routes.php
- CI3: application/config/routes.php

## 通用兜底
- 扫描 *Controller.php 与公开方法
- 从入口脚本（index.php）追踪请求分发
- 版本差异较大时以控制器扫描为主
