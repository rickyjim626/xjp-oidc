#!/bin/bash

# 资源服务器 API 测试脚本

API_BASE="http://localhost:8081"

echo "=== 资源服务器 API 测试 ==="
echo

echo "1. 测试公开端点（无需认证）"
echo "GET /"
curl -s $API_BASE/
echo -e "\n"

echo "GET /health"
curl -s $API_BASE/health | jq .
echo

echo "GET /api/public（无认证）"
curl -s $API_BASE/api/public | jq .
echo

echo "2. 测试受保护端点（无令牌，应返回 401）"
echo "GET /api/profile"
curl -s -w "\nHTTP Status: %{http_code}\n" $API_BASE/api/profile
echo

echo "3. 测试管理员端点（无令牌，应返回 401）"
echo "GET /api/admin/users"
curl -s -w "\nHTTP Status: %{http_code}\n" $API_BASE/api/admin/users
echo

echo "=== 使用示例令牌测试（需要真实令牌）==="
echo "设置环境变量 ACCESS_TOKEN 后重新运行脚本："
echo "export ACCESS_TOKEN=your-jwt-token"
echo

if [ ! -z "$ACCESS_TOKEN" ]; then
    echo "4. 使用令牌测试受保护端点"
    echo "GET /api/profile (with token)"
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" $API_BASE/api/profile | jq .
    echo

    echo "GET /api/protected (with token)"
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" $API_BASE/api/protected | jq .
    echo

    echo "5. 测试可选认证端点"
    echo "GET /api/public (with token)"
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" $API_BASE/api/public | jq .
    echo
fi

if [ ! -z "$ADMIN_TOKEN" ]; then
    echo "6. 使用管理员令牌测试"
    echo "GET /api/admin/users (with admin token)"
    curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $API_BASE/api/admin/users | jq .
    echo

    echo "GET /api/admin/settings (with admin token)"
    curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $API_BASE/api/admin/settings | jq .
    echo
fi